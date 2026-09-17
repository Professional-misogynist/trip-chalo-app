-- 0013_media_confirm_membership_hardening.sql
-- Phase 6 follow-up: adds a current-trip-membership re-check to
-- confirm_media_upload(), closing the window between "request upload"
-- and "confirm upload" during which a caller's membership could be
-- revoked while their upload was still pending.
--
-- CONTEXT
--
-- request_media_upload() (0012) already requires is_trip_member(p_trip_id)
-- at request time. confirm_media_upload() (0012) only re-checked:
--   - the media row exists
--   - uploader_id = auth.uid()
--   - processing_status = 'pending'
--   - the actual R2-reported size is within the ceiling
-- It never re-checked that the caller is STILL a member of the trip at
-- confirm time. trip_members is this project's sole authorization gate
-- for trip-scoped data (0003's own comment: "Sole source of truth for
-- 'can this user see this trip'"), so a caller removed from a trip
-- between requesting and confirming an upload could otherwise still
-- finalize that upload into 'ready' status for a trip they are no
-- longer a member of.
--
-- FIX
--
-- confirm_media_upload() is replaced with an IDENTICAL signature (no
-- caller-visible change to the RPC contract) that adds exactly one
-- additional check — is_trip_member(v_media.trip_id) — placed after the
-- uploader-ownership check and before the pending-state check. This
-- preserves existing behavior/ordering for every case 0012 already
-- covered: a non-uploader still gets 'Not authorized to confirm this
-- upload' first, unchanged. Only a caller who WAS the legitimate
-- uploader but has since left/been removed hits the new, distinct
-- rejection.
--
-- Everything else is preserved exactly as in 0012:
--   - row locking (SELECT ... FOR UPDATE)
--   - uploader ownership check
--   - pending-state check
--   - actual R2-verified size ceiling check, with 'failed' transition on
--     oversize
--   - server-only file_size_bytes / uploaded_at / processing_status writes
--   - storage_key is still never a parameter of this function and is
--     still never touched by it
--
-- GRANT REASONING
--
-- is_trip_member() is itself SECURITY DEFINER (0007) with search_path = ''.
-- Calling it from within another SECURITY DEFINER function's body does
-- not require a new grant: PostgreSQL evaluates EXECUTE privilege
-- against the role in effect at the time of the call, which for the
-- duration of a SECURITY DEFINER function's body is the function's
-- owner — and an owner's ability to call functions they themselves
-- created cannot be revoked via a PUBLIC/authenticated-scoped REVOKE.
-- This mirrors how is_trip_owner() is already called from inside
-- revoke_invitation() (0007) without any additional grant. (Reasoning
-- from standard PostgreSQL SECURITY DEFINER semantics; not
-- independently re-verified against a live database as part of this
-- migration.)
--
-- confirm_media_upload(uuid, bigint) keeps the exact signature from
-- 0012, so its existing revoke-then-grant-to-authenticated technically
-- remains in force across CREATE OR REPLACE. Restated explicitly below
-- anyway, matching this project's established convention of being
-- explicit rather than relying on inherited grants silently surviving.

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

  -- New in 0013: the uploader may have left, or been removed from, the
  -- trip after request_media_upload() admitted them but before this
  -- confirm call. trip_members is the sole authorization gate for
  -- trip-scoped data project-wide (0003) — a since-removed member must
  -- not be able to finalize a pending upload into a trip's media table.
  if not public.is_trip_member(v_media.trip_id) then
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

revoke execute on function public.confirm_media_upload(uuid, bigint) from public;
grant execute on function public.confirm_media_upload(uuid, bigint) to authenticated;