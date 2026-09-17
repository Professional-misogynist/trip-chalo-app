"use server";

import type { PostgrestError } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";
import { getCurrentUserId } from "@/modules/auth/session";
import { isTripId } from "@/modules/trips/validation";
import { isAllowedMimeType, validateDeclaredFileSize, sanitizeOriginalFilename } from "./validation";
import { createPresignedUploadUrl, headMediaObject } from "@/modules/storage/r2";

export type RequestUploadState = { error?: string; mediaId?: string; uploadUrl?: string };
export type ConfirmUploadState = { error?: string; success?: string };

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
 * Step 2 of the upload flow. Accepts ONLY mediaId — never a client-supplied
 * storageKey. The caller is authenticated first; storage_key is then read
 * from the database, filtered to rows this specific caller uploaded, and
 * only that database-derived value is ever passed to R2 HeadObject. The
 * actual size R2 reports is what reaches confirm_media_upload(); the SQL
 * function independently re-checks uploader_id and pending status itself,
 * so this app-level check is defense in depth, not the sole boundary.
 */
export async function confirmMediaUploadAction(input: {
  mediaId: string;
}): Promise<ConfirmUploadState> {
  const userId = await getCurrentUserId();
  if (!userId) {
    return { error: "You must be signed in to confirm this upload." };
  }

  const supabase = await createClient();

  // Scoped to uploader_id = the authenticated caller — narrower than
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
    // — one message for all three cases, so this cannot be used to probe
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

  const { error: rpcError } = await supabase.rpc("confirm_media_upload", {
    p_media_id: input.mediaId,
    p_actual_file_size_bytes: head.sizeBytes,
  });

  if (rpcError) {
    logDatabaseError("confirm_media_upload", rpcError);
    return { error: "Could not confirm the upload. Please try again." };
  }

  return { success: "Upload complete." };
}