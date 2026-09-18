-- 0014_confirm_media_upload_service_role_only.sql
-- Phase 6 security fix: closes a direct-RPC bypass of trusted R2
-- verification, identified in independent review.
--
-- THE GAP
--
-- confirm_media_upload(uuid, bigint) (0012, restated in 0013) was
-- granted EXECUTE to `authenticated`. Supabase's Data API exposes every
-- function in the public schema to any role holding EXECUTE on it
-- (supabase/config.toml: schemas = ["public", "graphql_public"]) via
-- POST /rest/v1/rpc/confirm_media_upload. This is independent of, and
-- not gated by, the Next.js server action (confirmMediaUploadAction,
-- media/actions.ts) that was *intended* to be the only caller.
--
-- confirm_media_upload() cannot itself verify anything against R2 --
-- Postgres has no network path to Cloudflare R2, by design (0012's own
-- header: "PostgreSQL = metadata + authorization, R2 = bytes"). The only
-- place the actual object's existence/size is verified is
-- headMediaObject() in the Next.js server action, called BEFORE the RPC.
--
-- Because the RPC was directly callable, any authenticated user could
-- skip that server action entirely and call
-- rpc('confirm_media_upload', { p_media_id, p_actual_file_size_bytes })
-- directly, supplying any p_actual_file_size_bytes within the type's
-- byte ceiling. uploader_id and current-membership checks inside the
-- function still held (this was never a cross-user authorization
-- break), but a user could transition their OWN pending row to 'ready'
-- for an object that was never uploaded, or whose real size differs
-- from what was reported -- defeating the documented invariant that a
-- 'ready' row implies a verified real R2 object. Because 'ready' media
-- is visible to every trip member (media_select_member, 0007), this
-- could inject bogus entries into a shared trip timeline.
--
-- THE FIX
--
-- Direct authenticated access to the "finalize as ready" capability is
-- removed. A new, differently-shaped overload of confirm_media_upload is
-- introduced, reachable ONLY by service_role -- a role that is never
-- exposed to the browser (see src/lib/supabase/service.ts) and is used
-- exclusively by the trusted Next.js server action, AFTER it has
-- independently verified the caller's identity (getCurrentUserId(),
-- itself backed by JWT-signature verification) and the real R2 object
-- (headMediaObject()).
--
-- Why a new overload rather than editing the existing function in
-- place: this project's convention (CLAUDE.md, section 8) is "Do not
-- casually edit already-applied migrations; use a new migration for
-- actual schema changes." A service-role caller carries no end-user JWT
-- by default, so auth.uid() (and, by extension, is_trip_member(), which
-- itself reads auth.uid() internally) would resolve to NULL for such a
-- call -- silently breaking every legitimate confirmation if the
-- existing function body were reused unmodified. The new overload
-- instead takes the already-verified caller id as an explicit parameter
-- (p_caller_id) and performs the identical ownership/membership/status/
-- size checks the original function did, substituting p_caller_id
-- everywhere the original used auth.uid(). This is safe specifically
-- because this overload is reachable only by service_role, which only
-- trusted server code can authenticate as -- an ordinary authenticated
-- client can never call this function at all, so it can never supply a
-- p_caller_id of its own choosing and have it trusted.
--
-- The original 2-argument confirm_media_upload(uuid, bigint) is left
-- defined (not dropped, consistent with this project's preference for
-- additive migrations) but its EXECUTE grant to `authenticated` is
-- revoked below, closing the direct-RPC path this migration exists to
-- fix. Nothing in this codebase calls the 2-argument form going forward.
--
-- Everything else -- row locking, uploader-ownership check, pending-
-- state check, the size ceiling and its 'failed' transition on oversize,
-- and the 0013 membership re-check -- is preserved exactly, just
-- re-expressed against p_caller_id instead of auth.uid()/is_trip_member().

-- ============ Close the direct-RPC path ============
revoke execute on function public.confirm_media_upload(uuid, bigint) from authenticated;
revoke execute on function public.confirm_media_upload(uuid, bigint) from public;

-- ============ New, service_role-only overload ============
create or replace function public.confirm_media_upload(
  p_media_id uuid,
  p_actual_file_size_bytes bigint,
  p_caller_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_media public.media;
  v_max_bytes bigint;
  v_is_member boolean;
begin
  if p_caller_id is null then
    raise exception 'Caller id is required';
  end if;

  select * into v_media
  from public.media
  where id = p_media_id
  for update;

  if v_media is null then
    raise exception 'Media not found';
  end if;

  if v_media.uploader_id is distinct from p_caller_id then
    raise exception 'Not authorized to confirm this upload';
  end if;

  -- Same membership invariant as 0013, expressed directly against
  -- p_caller_id rather than is_trip_member()/auth.uid(), which are not
  -- meaningful for a service_role-authenticated call (no end-user JWT
  -- is present, so auth.uid() would resolve to NULL here).
  select exists (
    select 1
    from public.trip_members
    where trip_id = v_media.trip_id
      and user_id = p_caller_id
  ) into v_is_member;

  if not v_is_member then
    raise exception 'You are no longer a member of this trip';
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

revoke execute on function public.confirm_media_upload(uuid, bigint, uuid) from public;
grant execute on function public.confirm_media_upload(uuid, bigint, uuid) to service_role;