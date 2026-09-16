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
 * Step 2. Independently verifies (server-side HeadObject — never the
 * browser's word) that the object exists and reads its actual size, then
 * hands that verified value to confirm_media_upload() (0012), the only
 * function allowed to mark a row 'ready'.
 */
export async function confirmMediaUploadAction(input: {
  mediaId: string;
  storageKey: string;
}): Promise<ConfirmUploadState> {
  const head = await headMediaObject(input.storageKey);
  if (!head) {
    return { error: "We couldn't find the uploaded file yet. Please try uploading again." };
  }

  const supabase = await createClient();
  const { error } = await supabase.rpc("confirm_media_upload", {
    p_media_id: input.mediaId,
    p_actual_file_size_bytes: head.sizeBytes,
  });

  if (error) {
    logDatabaseError("confirm_media_upload", error);
    return { error: "Could not confirm the upload. Please try again." };
  }

  return { success: "Upload complete." };
}