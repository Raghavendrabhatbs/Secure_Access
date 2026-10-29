const API_BASE = "/ai-api/admin/warpgate/sessions";
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

async function requestJson(url, options) {
  const response = await fetch(url, {
    ...options,
    credentials: "include",
  });
  if (!response.ok) {
    let detail;
    try {
      const payload = await response.json();
      detail = typeof payload?.detail === "string" ? payload.detail : "";
    } catch {
      detail = "";
    }
    throw new Error(detail || `Warpgate session request failed: HTTP ${response.status}`);
  }
  return response.json();
}

export async function getLiveWarpgateSessions() {
  const payload = await requestJson(`${API_BASE}/active`, { method: "GET" });
  if (!Array.isArray(payload?.sessions)) {
    throw new Error("Secure Access returned an invalid active-session list.");
  }
  return payload.sessions;
}

export async function terminateLiveWarpgateSession(sessionId, reason) {
  if (typeof sessionId !== "string" || !SESSION_ID.test(sessionId)) {
    throw new Error("The selected session has an invalid identifier.");
  }
  const payload = await requestJson(
    `${API_BASE}/${encodeURIComponent(sessionId)}/terminate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    },
  );
  if (
    !["confirmed", "already_ended", "unverified"].includes(payload?.status) ||
    payload?.session?.id?.toLowerCase() !== sessionId.toLowerCase()
  ) {
    throw new Error("Secure Access returned an invalid termination result.");
  }
  return payload;
}
