import "server-only";
import { createClient as createSupabaseClient } from "@supabase/supabase-js";

/**
 * Privileged Supabase client using the service-role key. This bypasses
 * RLS and is authorized via SECURITY DEFINER function grants that are
 * restricted to service_role -- never anon or authenticated.
 *
 * SERVER-ONLY: SUPABASE_SERVICE_ROLE_KEY must never be prefixed
 * NEXT_PUBLIC_ and must never be imported into a Client Component or any
 * file reachable from the browser bundle. This client exists solely so
 * that confirm_media_upload() (0014) -- a privileged, R2-verification-
 * gated state transition -- can be invoked ONLY from trusted server-side
 * code, never directly by an authenticated browser via the Supabase
 * Data API/RPC.
 *
 * The `import "server-only"` line above is a deliberate exception to
 * this project's usual preference for avoiding new dependencies (see
 * storage/r2.ts, which holds R2 credentials under the same class of
 * risk and explicitly decided against adding this same package). That
 * decision is not disturbed here. This file is treated differently
 * because a service-role key is a strictly more powerful credential
 * than R2's: it bypasses RLS across every table in the schema, not just
 * object storage. Today, this file's only importer is
 * media/actions.ts, a "use server" module -- Next.js's Server Actions
 * compilation already keeps this file's code and its imports out of
 * every client bundle, so this line changes nothing about current
 * behavior. Its purpose is to make a *future* refactor that
 * accidentally creates a client-reachable import path (something
 * next/headers-style guards would catch for lib/supabase/server.ts, but
 * that this file has no equivalent hard dependency for) fail at build
 * time instead of silently shipping.
 *
 * Unlike lib/supabase/client.ts and lib/supabase/server.ts, this client
 * carries no end-user session and performs no cookie handling: it is not
 * "the user acting as themselves" -- it is trusted application code
 * acting on the user's behalf AFTER that code has already independently
 * verified the caller's identity (getCurrentUserId()) and the real R2
 * object (headMediaObject()). Every function this client is used to call
 * must therefore take the caller's id as an explicit, already-verified
 * parameter rather than relying on auth.uid(), which is not populated
 * for service-role requests (there is no end-user JWT to read it from).
 */
export function createServiceClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !serviceRoleKey) {
    throw new Error(
      "Supabase service-role client is not configured (NEXT_PUBLIC_SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)."
    );
  }

  return createSupabaseClient(url, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}