"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import type { PostgrestError } from "@supabase/supabase-js";
import { createClient } from "@/lib/supabase/server";
import { getCurrentUserId } from "@/modules/auth/session";
import { deleteMediaObjectBestEffort } from "@/modules/storage/r2";
import {
  isTripId,
  validateTripName,
  validateTripDescription,
  validateTripDates,
} from "./validation";

/**
 * The values the user submitted, echoed back so a server-side validation
 * error does not discard what they typed: React resets an uncontrolled form
 * after a Server Action completes, so the form re-renders from defaultValue.
 * Feeding these back as those defaults is what preserves the input.
 */
export type TripFormValues = {
  name: string;
  description: string;
  startDate: string;
  endDate: string;
};

export type TripActionState = {
  error?: string;
  values?: TripFormValues;
};

function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function readTripFormValues(formData: FormData): TripFormValues {
  return {
    name: String(formData.get("name") ?? ""),
    description: String(formData.get("description") ?? ""),
    startDate: String(formData.get("startDate") ?? ""),
    endDate: String(formData.get("endDate") ?? ""),
  };
}

/**
 * Validation shared by create and edit — identical rules, and the server is
 * the authoritative check regardless of what the browser enforced.
 */
function validateTripFormValues(values: TripFormValues): string | null {
  const nameCheck = validateTripName(values.name);
  if (!nameCheck.valid) return nameCheck.error;

  const descriptionCheck = validateTripDescription(values.description);
  if (!descriptionCheck.valid) return descriptionCheck.error;

  const datesCheck = validateTripDates(values.startDate, values.endDate);
  if (!datesCheck.valid) return datesCheck.error;

  return null;
}

function tripColumnsFrom(values: TripFormValues) {
  return {
    name: values.name.trim(),
    description: emptyToNull(values.description),
    start_date: emptyToNull(values.startDate),
    end_date: emptyToNull(values.endDate),
  };
}

/**
 * Database failures are logged server-side and reported to the user as a
 * generic message. The log is what makes a failure diagnosable — the original
 * trip-creation RLS bug was invisible precisely because the real error was
 * swallowed here. Nothing from the error object reaches the browser: codes,
 * hints and constraint names describe the schema.
 */
function logDatabaseError(operation: string, error: PostgrestError): void {
  console.error(`[trips] ${operation} failed`, {
    code: error.code,
    message: error.message,
    details: error.details,
    hint: error.hint,
  });
}

export async function createTripAction(
  _prevState: TripActionState,
  formData: FormData
): Promise<TripActionState> {
  const values = readTripFormValues(formData);

  const validationError = validateTripFormValues(values);
  if (validationError) return { error: validationError, values };

  // Defense in depth only — the (app) layout and the proxy both already gate
  // unauthenticated users out before this action is reachable. owner_id is
  // derived solely from the server-verified JWT, never from client input.
  const ownerId = await getCurrentUserId();
  if (!ownerId) {
    return { error: "You must be signed in to create a trip.", values };
  }

  const supabase = await createClient();

  // Reading the new row back requires the trips SELECT policy to admit it,
  // because RETURNING makes PostgreSQL check SELECT policies against the new
  // row. That is what migration 0009 fixes — the owner's trip_members row is
  // created by an AFTER INSERT trigger and so does not exist yet at this
  // point. trips_insert_own still enforces owner_id = auth.uid().
  const { data, error } = await supabase
    .from("trips")
    .insert({ owner_id: ownerId, ...tripColumnsFrom(values) })
    .select("id")
    .single();

  if (error || !data) {
    if (error) logDatabaseError("create", error);
    return { error: "Could not create the trip. Please try again.", values };
  }

  revalidatePath("/trips");
  redirect(`/trips/${data.id}`);
}

export async function updateTripAction(
  _prevState: TripActionState,
  formData: FormData
): Promise<TripActionState> {
  const tripId = String(formData.get("tripId") ?? "");
  const values = readTripFormValues(formData);

  if (!isTripId(tripId)) {
    return { error: "This trip could not be found.", values };
  }

  const validationError = validateTripFormValues(values);
  if (validationError) return { error: validationError, values };

  const supabase = await createClient();

  // Ownership is enforced by trips_update_owner (RLS, 0007) — a non-owner's
  // update matches zero rows rather than erroring, so an empty result is
  // treated as "not authorized" below. owner_id is never part of this update,
  // so ownership can never be reassigned through it.
  const { data, error } = await supabase
    .from("trips")
    .update(tripColumnsFrom(values))
    .eq("id", tripId)
    .select("id");

  if (error) {
    logDatabaseError("update", error);
    return { error: "Could not update the trip. Please try again.", values };
  }

  if (data.length === 0) {
    // Same message whether the trip does not exist, is not visible to this
    // caller, or is visible but owned by someone else — the three cases must
    // stay indistinguishable.
    return { error: "Only the trip owner can edit this trip.", values };
  }

  revalidatePath("/trips");
  revalidatePath(`/trips/${tripId}`);
  redirect(`/trips/${tripId}`);
}

export async function deleteTripAction(
  _prevState: TripActionState,
  formData: FormData
): Promise<TripActionState> {
  const tripId = String(formData.get("tripId") ?? "");

  if (!isTripId(tripId)) {
    return { error: "This trip could not be found." };
  }

  const supabase = await createClient();

  // Captured BEFORE the trip delete below: 0003–0006's ON DELETE CASCADE
  // removes every media row for this trip synchronously within the same
  // DELETE FROM trips statement, so by the time that call returns, these
  // rows (and their storage_key values) are already gone and cannot be
  // read back. Gated by media_select_member (0007) exactly like any other
  // media read in this project — a caller who is a member but not the
  // owner can see this list regardless of whether their subsequent delete
  // attempt below succeeds, which discloses nothing beyond what the
  // existing media listing query already shows them.
  const { data: mediaRows, error: mediaLookupError } = await supabase
    .from("media")
    .select("storage_key")
    .eq("trip_id", tripId);

  if (mediaLookupError) {
    logDatabaseError("delete (media lookup)", mediaLookupError);
    // Not fatal — proceed with the trip delete attempt regardless. Losing
    // the ability to best-effort clean up R2 objects is not a reason to
    // block a trip deletion the owner is otherwise entitled to perform.
  }

  // Ownership is enforced by trips_delete_owner (RLS, 0007). Cascading
  // deletes on trip_members / invitations / media / messages happen at
  // the database level (0003–0006 foreign keys) — no application-level
  // metadata cleanup is needed or attempted here. This is a hard delete
  // of application metadata; R2 object cleanup for any media the trip
  // had is attempted, best-effort, below, and never affects whether this
  // delete itself succeeds.
  const { data, error } = await supabase
    .from("trips")
    .delete()
    .eq("id", tripId)
    .select("id");

  if (error) {
    logDatabaseError("delete", error);
    return { error: "Could not delete the trip. Please try again." };
  }

  if (data.length === 0) {
    return { error: "Only the trip owner can delete this trip." };
  }

  // DB deletion has already succeeded and is authoritative at this point —
  // nothing below can turn this request into a failure from the user's
  // perspective. R2 cleanup is strictly best-effort (PostgreSQL =
  // authoritative application state, R2 = object storage): each object is
  // attempted independently via a helper that swallows and logs its own
  // errors (trip_id attached for actionable context), and a failure here
  // is never reported as a trip-deletion failure.
  if (mediaRows && mediaRows.length > 0) {
    await Promise.all(
      mediaRows.map((row) => deleteMediaObjectBestEffort(row.storage_key, { tripId }))
    );
  }

  revalidatePath("/trips");
  redirect("/trips");
}