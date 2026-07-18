import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim();
const publishableKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY?.trim();

export const cloudConfigurationError =
  !supabaseUrl || !publishableKey
    ? "Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY before starting BoundaryCI Cloud."
    : null;

export const supabase: SupabaseClient | null =
  supabaseUrl && publishableKey
    ? createClient(supabaseUrl, publishableKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
        },
      })
    : null;

export const ingestionUrl =
  import.meta.env.VITE_BOUNDARYCI_INGEST_URL?.trim() ||
  (supabaseUrl ? `${supabaseUrl.replace(/\/$/, "")}/functions/v1/ingest-scan` : "");

export function requireSupabase(): SupabaseClient {
  if (!supabase) throw new Error(cloudConfigurationError ?? "BoundaryCI Cloud is unavailable.");
  return supabase;
}
