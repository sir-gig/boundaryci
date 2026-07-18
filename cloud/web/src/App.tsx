import type { Session } from "@supabase/supabase-js";
import { useEffect, useState } from "react";
import { AuthScreen } from "./components/AuthScreen";
import { Brand } from "./components/Brand";
import { Dashboard } from "./components/Dashboard";
import { PublicSite } from "./components/PublicSite";
import { cloudConfigurationError, supabase } from "./lib/supabase";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(Boolean(supabase));
  const publicUrl = import.meta.env.BASE_URL;
  const requestedAuthMode = new URLSearchParams(window.location.search).get("auth");
  const authMode = requestedAuthMode === "signup" || requestedAuthMode === "signin"
    ? requestedAuthMode
    : null;

  useEffect(() => {
    if (!supabase) return;
    let mounted = true;
    void supabase.auth.getSession().then(({ data }) => {
      if (mounted) {
        setSession(data.session);
        setLoading(false);
      }
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setLoading(false);
    });
    return () => {
      mounted = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  if (loading) {
    return <PublicSite baseUrl={publicUrl} />;
  }

  if (!session && !authMode) return <PublicSite baseUrl={publicUrl} />;

  if (cloudConfigurationError) {
    return (
      <main className="configuration-screen">
        <Brand />
        <div className="configuration-card">
          <span className="eyebrow">Configuration required</span>
          <h1>Connect the Cloud dashboard</h1>
          <p>{cloudConfigurationError}</p>
          <pre><code>cp .env.example .env.local</code></pre>
        </div>
      </main>
    );
  }

  if (session) return <Dashboard session={session} />;
  if (authMode) return <AuthScreen initialMode={authMode} publicUrl={publicUrl} />;
  return <PublicSite baseUrl={publicUrl} />;
}
