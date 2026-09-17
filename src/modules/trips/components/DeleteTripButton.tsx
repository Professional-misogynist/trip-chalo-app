"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import { deleteTripAction, type TripActionState } from "@/modules/trips/actions";

const initialState: TripActionState = {};

export function DeleteTripButton({
  tripId,
  tripName,
}: {
  tripId: string;
  tripName: string;
}) {
  const [confirming, setConfirming] = useState(false);
  const [state, formAction, isPending] = useActionState(deleteTripAction, initialState);

  const triggerRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLParagraphElement>(null);

  // Move focus into the confirmation panel when it appears, and back to
  // the trigger when it's dismissed — this is an inline, non-modal panel
  // (no focus trap, background stays reachable), so focus is guided
  // rather than forced, and no dialog role is used.
  useEffect(() => {
    if (confirming) {
      headingRef.current?.focus();
    } else {
      triggerRef.current?.focus();
    }
  }, [confirming]);

  if (!confirming) {
    return (
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setConfirming(true)}
        className="rounded-md border border-red-300 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50"
      >
        Delete
      </button>
    );
  }

  return (
    <div
      aria-live="assertive"
      className="rounded-md border border-red-300 bg-red-50 p-4 text-sm"
    >
      <p ref={headingRef} tabIndex={-1} className="font-medium text-red-800 focus:outline-none">
        Delete &ldquo;{tripName}&rdquo;?
      </p>
      <p className="mt-1 text-red-700">
        This permanently removes the trip along with its members, invitations,
        messages, and media records. This can&rsquo;t be undone.
      </p>
      <p className="mt-1 text-xs text-red-600">
        Any photos or videos in this trip are removed too. Trip records are
        deleted immediately; the underlying files are then cleaned up right
        after and may take a short time to fully clear.
      </p>

      {state.error ? (
        <p role="alert" className="mt-2 text-red-800">
          {state.error}
        </p>
      ) : null}

      <form action={formAction} className="mt-3 flex gap-2">
        <input type="hidden" name="tripId" value={tripId} />
        <button
          type="submit"
          disabled={isPending}
          className="rounded-md bg-red-600 px-3 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-60"
        >
          {isPending ? "Deleting…" : "Yes, delete permanently"}
        </button>
        <button
          type="button"
          onClick={() => setConfirming(false)}
          disabled={isPending}
          className="rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Cancel
        </button>
      </form>
    </div>
  );
}