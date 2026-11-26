import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { corsHeaders } from "jsr:@supabase/supabase-js@2/cors";

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  const url = Deno.env.get("SUPABASE_URL") ?? "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const authHeader = req.headers.get("Authorization") ?? "";
  const admin = createClient(url, serviceKey);
  const userClient = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });
  try {
    if (req.method === "GET") {
      const { count } = await admin.from("confidential_documents").select("id", { count: "exact", head: true });
      await admin.from("service_heartbeats").insert({
        source: "supabase-edge",
        status: "online",
        details: "24/7 Edge runtime health heartbeat",
      });
      return new Response(
        JSON.stringify({
          status: "online",
          runtime: "supabase-edge-24x7",
          project_ref: "fpidtcofamgfyyiwyshy",
          documents_count: count ?? 0,
          timestamp: new Date().toISOString(),
        }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    const body = await req.json().catch(() => ({}));
    const action = body?.action || "ping";
    if (action === "documents") {
      const { data, error } = await userClient
        .from("confidential_documents")
        .select("slug,title,classification,content")
        .order("id", { ascending: true });
      if (error) throw error;
      return new Response(JSON.stringify({ status: "success", documents: data ?? [] }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    await admin.from("service_heartbeats").insert({
      source: "supabase-edge-ping",
      status: "online",
      details: "Keepalive action: " + String(action),
    });
    return new Response(
      JSON.stringify({
        status: "online",
        runtime: "supabase-edge-24x7",
        project_ref: "fpidtcofamgfyyiwyshy",
        timestamp: new Date().toISOString(),
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ status: "error", message: err instanceof Error ? err.message : String(err) }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
