const AUDIT_EVENTS_API = "/@warpgate/rrweb/api/audit/events";

export async function logSecureAccessEvent(category, action, details = {}) {
  try {
    const response = await fetch(AUDIT_EVENTS_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ category, action, details }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (error) {
    console.error("Unable to record SecureAccess audit event:", error);
  }
}

export async function getSecureAccessAuditEvents({
  limit = 200,
  search = "",
} = {}) {
  const query = new URLSearchParams({
    limit: String(limit),
    search,
  });
  const response = await fetch(`${AUDIT_EVENTS_API}?${query.toString()}`, {
    method: "GET",
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch SecureAccess audit events: HTTP ${response.status}`,
    );
  }

  const events = await response.json();
  if (!Array.isArray(events)) {
    throw new Error("SecureAccess returned an invalid audit events response.");
  }
  return events;
}
