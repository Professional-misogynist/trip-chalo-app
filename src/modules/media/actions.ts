"use server";

import { revalidatePath } from "next/cache";
import type { PostgrestError } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";
import { createServiceClient } from "@/lib/supabase/service";
import { getCurrentUserId } from "@/modules/auth/session";
import { isTripId } from "@/modules/trips/validation";
import {
  isAllowedMimeType,
  isMediaId,
  validateDeclaredFileSize,
  sanitizeOriginalFilename,
} from "./validation";
import {
  createPresignedUploadUrl,
  headMediaObject,
  deleteMediaObjectBestEffort,
} from "@/modules/storage/r2";

export type RequestUploadState = { error?: string; mediaId?: string; uploadUrl?: string };
export type ConfirmUploadState = { error?: string; success?: string };
export type DeleteMediaState = { error?: string; success?: string };

function logDatabaseError(operation: string, error: PostgrestError): void {
  console.error(`[media] ${operation} failed`, {
    code: error.code,
    message: error.message,
    details: error.details,
    hint: error.hint,
  });
}

/**
 * Step 1. Validates the request as a fast pre-check, then delegates row
 * creation entirely to request_media_upload() (0012), which independently
 * re-checks membership, MIME allowlist, and size ceiling server-side
 * regardless of what passed here. Issues a presigned PUT URL for the
 * server-generated storage_key it gets back.
 */
export async function requestMediaUploadAction(input: {
  tripId: string;
  mimeType: string;
  fileSizeBytes: number;
  originalFilename?: string | null;
  capturedAt?: string | null;
  width?: number | null;
  height?: number | null;
  durationSeconds?: number | null;
}): Promise<RequestUploadState> {
  const { tripId, mimeType, fileSizeBytes } = input;

  if (!isTripId(tripId)) return { error: "This trip could not be found." };
  if (!isAllowedMimeType(mimeType)) return { error: "This file type isn't supported." };

  const sizeCheck = validateDeclaredFileSize(mimeType, fileSizeBytes);
  if (!sizeCheck.valid) return { error: sizeCheck.error };

  const userId = await getCurrentUserId();
  if (!userId) return { error: "You must be signed in to upload media." };

  const supabase = await createClient();

  const { data, error } = await supabase
    .rpc("request_media_upload", {
      p_trip_id: tripId,
      p_mime_type: mimeType,
      p_file_size_bytes: fileSizeBytes,
      p_original_filename: sanitizeOriginalFilename(input.originalFilename),
      p_captured_at: input.capturedAt ?? null,
      p_width: input.width ?? null,
      p_height: input.height ?? null,
      p_duration_seconds: input.durationSeconds ?? null,
    })
    .single();

  if (error || !data) {
    if (error) logDatabaseError("request_media_upload", error);
    return { error: "Could not start the upload. Please try again." };
  }

  const row = data as { media_id: string; storage_key: string };

  try {
    const uploadUrl = await createPresignedUploadUrl(row.storage_key, mimeType);
    return { mediaId: row.media_id, uploadUrl };
  } catch (err) {
    console.error("[media] presign failed", err);
    return { error: "Could not prepare the upload. Please try again." };
  }
}

/**
 * Step 2 of the upload flow. Accepts ONLY mediaId -- never a client-supplied
 * storageKey. The caller is authenticated first; storage_key is then read
 * from the database, filtered to rows this specific caller uploaded, and
 * only that database-derived value is ever passed to R2 HeadObject.
 *
 * The actual size R2 reports (head.sizeBytes) is then handed to
 * confirm_media_upload() -- but as of 0014, that RPC can no longer be
 * called directly by an authenticated client via the Supabase Data API:
 * its EXECUTE grant to `authenticated` was revoked, and the only reachable
 * overload is granted to `service_role` alone. This function is therefore
 * now the SOLE path by which a media row can ever reach 'ready' status --
 * a caller cannot skip the headMediaObject() verification above by
 * calling the RPC directly, because they cannot call it at all.
 *
 * userId is passed explicitly as p_caller_id because a service_role call
 * carries no end-user JWT for the SQL function to read via auth.uid();
 * userId was already verified above via getCurrentUserId(), which checks
 * the signed session JWT, so it is safe to trust here as the caller's
 * true identity. The SQL function independently re-checks uploader_id,
 * current trip membership, and pending status against that id itself.
 */
export async function confirmMediaUploadAction(input: {
  mediaId: string;
}): Promise<ConfirmUploadState> {
  const userId = await getCurrentUserId();
  if (!userId) {
    return { error: "You must be signed in to confirm this upload." };
  }

  const supabase = await createClient();

  // Scoped to uploader_id = the authenticated caller -- narrower than
  // media_select_member RLS, which would let ANY fellow trip member read
  // this row (and its storage_key) even though they didn't upload it.
  // This filter is what prevents a co-member from confirming or probing
  // someone else's pending upload through this action.
  const { data, error } = await supabase
    .from("media")
    .select("storage_key, processing_status")
    .eq("id", input.mediaId)
    .eq("uploader_id", userId)
    .maybeSingle();

  if (error) {
    logDatabaseError("confirm_media_upload (lookup)", error);
    return { error: "Could not confirm the upload. Please try again." };
  }

  if (!data) {
    // Row doesn't exist, isn't visible, or isn't this caller's own upload
    // -- one message for all three cases, so this cannot be used to probe
    // for the existence of another user's media id.
    return { error: "This upload could not be found." };
  }

  if (data.processing_status !== "pending") {
    return { error: "This upload has already been processed." };
  }

  // Only the database-derived storage_key is ever used here.
  const head = await headMediaObject(data.storage_key);
  if (!head) {
    return { error: "We couldn't find the uploaded file yet. Please try uploading again." };
  }

  // Uses the service-role client (0014) rather than the caller's own
  // session client: confirm_media_upload's only remaining reachable
  // overload is granted to service_role, precisely so that no
  // authenticated browser client can call it directly and skip the
  // headMediaObject() verification above.
  const serviceClient = createServiceClient();
  const { error: rpcError } = await serviceClient.rpc("confirm_media_upload", {
    p_media_id: input.mediaId,
    p_actual_file_size_bytes: head.sizeBytes,
    p_caller_id: userId,
  });

  if (rpcError) {
    // confirm_media_upload (0012/0013/0014) distinguishes several
    // rejection reasons in its exception text, but this action never
    // forwards that text to the browser -- every RPC error collapses to
    // one generic message here, with detail only reaching server logs.
    logDatabaseError("confirm_media_upload", rpcError);
    return { error: "Could not confirm the upload. Please try again." };
  }

  return { success: "Upload complete." };
}

/**
 * Deletes a media item. Authorization is entirely RLS-enforced by
 * media_delete_uploader_or_owner (0007: uploader_id = auth.uid() OR
 * is_trip_owner(trip_id)) -- this action adds no authorization logic of
 * its own and does not change who may delete what.
 *
 * DELETE ... RETURNING requires the deleted row to satisfy the table's
 * SELECT policy to be returned at all (the same RETURNING/RLS
 * interaction documented in 0009 for trips). As of 0015,
 * media_select_member also admits a row when uploader_id = auth.uid(),
 * so a departed uploader deleting their own historical media can now
 * have that delete correctly reported back via RETURNING, matching what
 * media_delete_uploader_or_owner already permitted.
 *
 * DB deletion is authoritative and reported as successful regardless of
 * what happens next; R2 cleanup below is strictly best-effort.
 */
export async function deleteMediaAction(
  _prevState: DeleteMediaState,
  formData: FormData
): Promise<DeleteMediaState> {
  const mediaId = String(formData.get("mediaId") ?? "");

  if (!isMediaId(mediaId)) {
    return { error: "This media item could not be found." };
  }

  const supabase = await createClient();

  const { data, error } = await supabase
    .from("media")
    .delete()
    .eq("id", mediaId)
    .select("storage_key, trip_id")
    .maybeSingle();

  if (error) {
    logDatabaseError("delete", error);
    return { error: "Could not delete this media item. Please try again." };
  }

  if (!data) {
    // Same message whether the row doesn't exist, isn't visible, or is
    // visible but not deletable by this caller -- mirrors the
    // indistinguishability convention used elsewhere in this project.
    return {
      error: "This media item could not be found, or you don't have permission to delete it.",
    };
  }

  // Best-effort only -- a failure here is logged internally and never
  // turns this already-successful DB delete into a reported failure.
  await deleteMediaObjectBestEffort(data.storage_key, { mediaId });

  revalidatePath(`/trips/${data.trip_id}`);

  return { success: "Media deleted." };
}