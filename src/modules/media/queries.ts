import { createClient } from "@/lib/supabase/server";
import { createPresignedDownloadUrl } from "@/modules/storage/r2";
import { isTripId } from "@/modules/trips/validation";

export type MediaType = "photo" | "video";
export type MediaProcessingStatus = "pending" | "processing" | "ready" | "failed";

export type Media = {
  id: string;
  trip_id: string;
  uploader_id: string | null;
  storage_key: string;
  media_type: MediaType;
  original_filename: string | null;
  mime_type: string;
  file_size_bytes: number;
  width: number | null;
  height: number | null;
  duration_seconds: number | null;
  captured_at: string | null;
  uploaded_at: string | null;
  processing_status: MediaProcessingStatus;
  created_at: string;
};

const MEDIA_COLUMNS =
  "id, trip_id, uploader_id, storage_key, media_type, original_filename, mime_type, file_size_bytes, width, height, duration_seconds, captured_at, uploaded_at, processing_status, created_at";

/**
 * Ready media for a trip, in chronology_at order (0012's generated
 * COALESCE(captured_at, uploaded_at) column), id as a deterministic
 * tie-break. media_select_member (0007) is what restricts this to trip
 * members. 'pending'/'failed' rows are excluded — no in-progress-upload
 * UI exists in this phase, and nothing should render an unconfirmed row
 * as real media.
 */
export async function listTripMedia(tripId: string): Promise<Media[]> {
  if (!isTripId(tripId)) return [];

  const supabase = await createClient();
  const { data, error } = await supabase
    .from("media")
    .select(MEDIA_COLUMNS)
    .eq("trip_id", tripId)
    .eq("processing_status", "ready")
    .order("chronology_at", { ascending: true })
    .order("id", { ascending: true });

  if (error) {
    console.error("[media] listTripMedia failed", {
      code: error.code, message: error.message, details: error.details, hint: error.hint,
    });
    throw new Error("Failed to load media");
  }

  return data;
}

/**
 * Fresh, short-lived download URL for one media item. Re-checks
 * membership via the same media_select_member RLS boundary immediately
 * before issuing the URL — per the approved decision, this is never
 * cached or reused across requests.
 */
export async function getMediaDownloadUrl(mediaId: string): Promise<string | null> {
  const supabase = await createClient();

  const { data, error } = await supabase
    .from("media")
    .select("storage_key, processing_status")
    .eq("id", mediaId)
    .eq("processing_status", "ready")
    .maybeSingle();

  if (error) {
    console.error("[media] getMediaDownloadUrl lookup failed", {
      code: error.code, message: error.message, details: error.details, hint: error.hint,
    });
    throw new Error("Failed to load media");
  }

  if (!data) return null;
  return createPresignedDownloadUrl(data.storage_key);
}