export type ValidationResult = { valid: true } | { valid: false; error: string };

/**
 * Mirrors media_type_for_mime() in migration 0012, kept in sync manually.
 * This is a fast, friendly pre-check before round-tripping to the
 * database — the SQL function in 0012 is the actual authorization
 * boundary and is re-checked regardless of what passes here.
 */
export const ALLOWED_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/heic",
  "image/heif",
  "video/mp4",
  "video/quicktime",
  "video/webm",
] as const;

export type AllowedMimeType = (typeof ALLOWED_MIME_TYPES)[number];

const MAX_PHOTO_BYTES = 25 * 1024 * 1024;  // mirrors max_media_bytes_for_type('photo')
const MAX_VIDEO_BYTES = 200 * 1024 * 1024; // mirrors max_media_bytes_for_type('video')
const MAX_FILENAME_LENGTH = 255;

export function isAllowedMimeType(mimeType: string): mimeType is AllowedMimeType {
  return (ALLOWED_MIME_TYPES as readonly string[]).includes(mimeType);
}

function isPhotoMime(mimeType: string): boolean {
  return mimeType.startsWith("image/");
}

export function validateDeclaredFileSize(mimeType: string, fileSizeBytes: number): ValidationResult {
  if (!Number.isFinite(fileSizeBytes) || fileSizeBytes <= 0) {
    return { valid: false, error: "Invalid file size." };
  }
  const max = isPhotoMime(mimeType) ? MAX_PHOTO_BYTES : MAX_VIDEO_BYTES;
  if (fileSizeBytes > max) {
    return { valid: false, error: `File exceeds the ${Math.floor(max / (1024 * 1024))} MB limit.` };
  }
  return { valid: true };
}

/**
 * original_filename is untrusted display metadata (point 3 of the
 * review): length-limited and never used to build a storage key.
 */
export function sanitizeOriginalFilename(filename: string | null | undefined): string | null {
  if (!filename) return null;
  const trimmed = filename.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, MAX_FILENAME_LENGTH);
}
