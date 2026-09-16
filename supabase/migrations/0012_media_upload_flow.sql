-- 0012_media_upload_flow.sql
-- Phase 6: authoritative media upload flow via SECURITY DEFINER RPCs.
-- request_media_upload() / confirm_media_upload() become the only paths
-- that create or finalize media rows. Direct client INSERT is revoked;
-- UPDATE was never granted (0008) and remains ungranted.
--
-- Why direct INSERT must go: uploader_id, storage_key, media_type, and
-- processing_status must never be trusted from client input. A client
-- with authenticated+insert Data API access to media could otherwise
-- forge uploader_id, invent a storage_key colliding with another trip's
-- object, or mark a fabricated row 'ready' without ever uploading bytes.
-- request_media_upload() derives every one of those fields itself.
--
-- Two-step flow:
--   1. request_media_upload(...) validates membership, MIME type, and
--      declared size; inserts a 'pending' row with a server-generated
--      storage_key; returns (media_id, storage_key) so the app can obtain
--      a presigned PUT URL for that exact key.
--   2. confirm_media_upload(...) is called by the app AFTER it has
--      independently verified (via a server-side R2 HeadObject call,
--      never from the browser) that the object exists, using the
--      server-reported actual size. Transitions pending -> ready, sets
--      uploaded_at, and overwrites file_size_bytes with the verified
--      actual size (the declared size at request time is advisory only).
--
-- Residual limitation (documented per the approved architecture review):
-- a presigned PUT URL cannot itself enforce a byte-count ceiling before
-- the browser uploads — this project isn't using a signed POST policy
-- with content-length-range conditions, and R2/S3 presigned PUT alone has
-- no independent size cap. The ceiling is therefore enforced at two
-- points that together bound the actual risk: (a) request time, against
-- the client's declared size, before any URL is issued; and (b) confirm
-- time, by refusing to mark the row 'ready' (transitioning it to 'failed'
-- instead) if the verified actual R2 object size exceeds the same
-- ceiling. A caller who lies about size at request time and uploads an
-- oversized object can occupy R2 storage temporarily, but can never
-- obtain a 'ready' row for it, and every read path in this phase only
-- surfaces 'ready' rows. Enforcing the ceiling during the PUT itself
-- would require Worker/edge-level request inspection — out of scope here.

-- ============ chronology: COALESCE(captured_at, uploaded_at) ============
-- A generated column rather than query-time ORDER BY on two separate
-- columns: ordering by (captured_at asc, uploaded_at asc) as two sort
-- keys would group every row that HAS a captured_at before every row
-- that doesn't, which is not the same as sorting by a single coalesced
-- instant — a captured_at-only row and an uploaded_at-only row need to be
-- able to interleave correctly. A stored generated column computes the
-- single correct sort key once, indexably, and can never drift from the
-- two source columns.
alter table public.media
  add column chronology_at timestamptz generated always as (coalesce(captured_at, uploaded_at)) stored;

create index media_trip_id_chronology_idx
  on public.media (trip_id, chronology_at, id);

-- ============ MIME allowlist -> media_type (single source of truth) ============
-- Ensures media_type and mime_type can never disagree: media_type is
-- always derived here, never accepted as client input in request_media_upload.
create or replace function public.media_type_for_mime(p_mime_type text)
returns text
language sql
immutable
set search_path = ''
as $$
  select case p_mime_type
    when 'image/jpeg' then 'photo'
    when 'image/png' then 'photo'
    when 'image/webp' then 'photo'
    when 'image/heic' then 'photo'
    when 'image/heif' then 'photo'
    when 'video/mp4' then 'video'
    when 'video/quicktime' then 'video'
    when 'video/webm' then 'video'
    else null
  end;
$$;

-- Internal helper only — called from request_media_upload (SECURITY
-- DEFINER), never granted directly to authenticated or public.
revoke execute on function public.media_type_for_mime(text) from public;

-- ============ Size ceilings (single source of truth) ============
-- A function rather than a bare constant duplicated in two migrations'
-- worth of validation logic, so request-time and confirm-time checks can
-- never drift apart.
create or replace function public.max_media_bytes_for_type(p_media_type text)
returns bigint
language sql
immutable
set search_path = ''
as $$
  select case p_media_type
    when 'photo' then 26214400::bigint   -- 25 MiB
    when 'video' then 209715200::bigint  -- 200 MiB
    else 0::bigint
  end;
$$;

revoke execute on function public.max_media_bytes_for_type(text) from public;

-- ============ request_media_upload ============
-- storage_key shape: <trip_id>/<media_id>.<ext>. Both path segments are
-- server-generated UUIDs; original_filename is never placed into the key
-- (point 3 of the review: untrusted metadata, never used for the R2 key),
-- so a malicious filename cannot path-traverse or collide with another
-- trip's object.
create or replace function public.request_media_upload(
  p_trip_id uuid,
  p_mime_type text,
  p_file_size_bytes bigint,
  p_original_filename text default null,
  p_captured_at timestamptz default null,
  p_width integer default null,
  p_height integer default null,
  p_duration_seconds numeric default null
)
returns table (media_id uuid, storage_key text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_media_type text;
  v_max_bytes bigint;
  v_media_id uuid;
  v_storage_key text;
  v_extension text;
  v_safe_filename text;
begin
  if not public.is_trip_member(p_trip_id) then
    raise exception 'You must be a member of this trip to upload media';
  end if;

  v_media_type := public.media_type_for_mime(p_mime_type);
  if v_media_type is null then
    raise exception 'Unsupported file type: %', p_mime_type;
  end if;

  if p_file_size_bytes is null or p_file_size_bytes <= 0 then
    raise exception 'Invalid file size';
  end if;

  v_max_bytes := public.max_media_bytes_for_type(v_media_type);
  if p_file_size_bytes > v_max_bytes then
    raise exception 'File exceeds the % byte limit for %', v_max_bytes, v_media_type;
  end if;

  -- Untrusted display metadata only (point 3 of the review) — length-
  -- capped, never used to build storage_key.
  v_safe_filename := left(nullif(trim(p_original_filename), ''), 255);

  v_extension := case p_mime_type
    when 'image/jpeg' then 'jpg'
    when 'image/png' then 'png'
    when 'image/webp' then 'webp'
    when 'image/heic' then 'heic'
    when 'image/heif' then 'heif'
    when 'video/mp4' then 'mp4'
    when 'video/quicktime' then 'mov'
    when 'video/webm' then 'webm'
  end;

  v_media_id := gen_random_uuid();
  v_storage_key := p_trip_id::text || '/' || v_media_id::text || '.' || v_extension;

  insert into public.media (
    id, trip_id, uploader_id, storage_key, media_type, original_filename,
    mime_type, file_size_bytes, width, height, duration_seconds,
    captured_at, processing_status
  )
  values (
    v_media_id, p_trip_id, auth.uid(), v_storage_key, v_media_type, v_safe_filename,
    p_mime_type, p_file_size_bytes, p_width, p_height, p_duration_seconds,
    p_captured_at, 'pending'
  );

  return query select v_media_id, v_storage_key;
end;
$$;

revoke execute on function public.request_media_upload(uuid, text, bigint, text, timestamptz, integer, integer, numeric) from public;
grant execute on function public.request_media_upload(uuid, text, bigint, text, timestamptz, integer, integer, numeric) to authenticated;

-- ============ confirm_media_upload ============
-- p_actual_file_size_bytes MUST come from a server-side R2 HeadObject
-- call the application performs (never from the browser) — this function
-- cannot itself reach into R2, so its guarantee is only as strong as that
-- caller discipline (documented in application code too). It still
-- enforces everything it CAN verify from the row itself: caller must be
-- the original uploader, the row must currently be pending, and the
-- confirmed size must not exceed the same ceiling used at request time —
-- closing the gap where a client under-declares size at request time and
-- then uploads something larger.
create or replace function public.confirm_media_upload(
  p_media_id uuid,
  p_actual_file_size_bytes bigint
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_media public.media;
  v_max_bytes bigint;
begin
  select * into v_media
  from public.media
  where id = p_media_id
  for update;

  if v_media is null then
    raise exception 'Media not found';
  end if;

  if v_media.uploader_id is distinct from auth.uid() then
    raise exception 'Not authorized to confirm this upload';
  end if;

  if v_media.processing_status <> 'pending' then
    raise exception 'This upload has already been processed';
  end if;

  if p_actual_file_size_bytes is null or p_actual_file_size_bytes <= 0 then
    raise exception 'Invalid confirmed file size';
  end if;

  v_max_bytes := public.max_media_bytes_for_type(v_media.media_type);
  if p_actual_file_size_bytes > v_max_bytes then
    update public.media set processing_status = 'failed' where id = p_media_id;
    raise exception 'Uploaded file exceeds the % byte limit for %', v_max_bytes, v_media.media_type;
  end if;

  update public.media
  set processing_status = 'ready',
      file_size_bytes = p_actual_file_size_bytes,
      uploaded_at = now()
  where id = p_media_id;
end;
$$;

revoke execute on function public.confirm_media_upload(uuid, bigint) from public;
grant execute on function public.confirm_media_upload(uuid, bigint) to authenticated;

-- ============ Lock down direct client INSERT ============
-- media_insert_member (0007) remains defined but is now unreachable in
-- practice: Postgres checks table-level grants before RLS is evaluated,
-- so revoking INSERT here is sufficient. Left un-dropped deliberately —
-- dropping an applied policy is its own review surface and buys nothing
-- once the grant itself is gone.
revoke insert on public.media from authenticated;

-- SELECT and DELETE (0008) are unchanged: media_select_member and
-- media_delete_uploader_or_owner (0007) remain the read/delete boundary,
-- per the approved decision to keep existing DELETE RLS/grant as-is.