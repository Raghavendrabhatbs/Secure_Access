const WARPGATE_API = "/warpgate-api";
const WARPGATE_ADMIN_API = "/warpgate-admin-api";

export function normalizeWarpgateLogId(value) {
  if (typeof value === "string" && value) {
    return value;
  }
  if (Number.isSafeInteger(value)) {
    return String(value);
  }
  if (
    value?.type !== "Buffer" ||
    !Array.isArray(value.data) ||
    value.data.length !== 16 ||
    !value.data.every(
      (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255,
    )
  ) {
    return null;
  }

  const hex = value.data
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function normalizeWarpgateLogTarget(value) {
  return typeof value === "string" && /^warpgate_[a-z0-9_]+::/.test(value)
    ? "SecureAccess"
    : value;
}

export function getWarpgateAccessOrigin(hostname) {
  if (typeof hostname !== "string" || !hostname.trim()) {
    throw new Error("A browser hostname is required for SecureAccess.");
  }

  const origin = new URL("https://localhost:8888");
  origin.hostname = hostname;
  return origin.origin;
}

/* =========================================================
   AUTHENTICATION
========================================================= */

export async function loginToWarpgate(username, password) {
  const response = await fetch(
    `${WARPGATE_API}/auth/login`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      credentials: "include",

      body: JSON.stringify({
        username,
        password,
      }),
    }
  );

  if (response.status === 201) {
    return {
      success: true,
    };
  }

  if (response.status === 401) {
    const data = await response.json();

    return {
      success: false,
      ...data,
    };
  }

  throw new Error(
    `SecureAccess sign-in failed: ${response.status}`
  );
}


export async function getWarpgateInfo() {
  const response = await fetch(
    `${WARPGATE_API}/info`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch SecureAccess information: ${response.status}`
    );
  }

  return response.json();
}

export async function logoutFromWarpgate() {
  const response = await fetch(`${WARPGATE_API}/auth/logout`, {
    method: "POST",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`SecureAccess sign-out failed: ${response.status}`);
  }
}


/* =========================================================
   USERS
========================================================= */

export async function getWarpgateUsers(search = "") {
  const query = search
    ? `?search=${encodeURIComponent(search)}`
    : "";

  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users${query}`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch users: ${response.status}`
    );
  }

  return response.json();
}

export async function getWarpgateUser(userId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users/${userId}`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch user: ${response.status}`
    );
  }

  return response.json();
}

export async function deleteWarpgateUser(userId) {
  const response = await fetch(`${WARPGATE_ADMIN_API}/users/${userId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`Failed to delete user: ${response.status}`);
  }
}

/* =========================================================
   USER ACCESS ROLES
========================================================= */

export async function getWarpgateUserRoles(userId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users/${userId}/roles`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch user roles: ${response.status}`
    );
  }

  return response.json();
}


/* =========================================================
   USER ADMIN ROLES
========================================================= */

export async function getWarpgateUserAdminRoles(userId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users/${userId}/admin-roles`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch admin roles: ${response.status}`
    );
  }

  return response.json();

}

export async function getWarpgateUserApplicationRole(userId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users/${userId}/application-role`,
    {
      method: "GET",
      credentials: "include",
    }
  );
  if (!response.ok) {
    throw new Error(`Failed to fetch application role: ${response.status}`);
  }
  return response.json();
}

export async function setWarpgateUserApplicationRole(userId, applicationRole) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/users/${userId}/application-role`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ application_role: applicationRole }),
    }
  );
  if (!response.ok) {
    throw new Error(`Failed to set application role: ${response.status}`);
  }
  return response.json();
}

/* =========================================================
   ACCESS ROLES
========================================================= */

export async function getWarpgateRoles() {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/roles`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch roles: ${response.status}`
    );
  }

  return response.json();
}

export async function deleteWarpgateAccessRole(roleId) {
  const response = await fetch(`${WARPGATE_ADMIN_API}/role/${roleId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`Failed to delete access role: ${response.status}`);
  }
}

/* =========================================================
   ADMIN ROLES
========================================================= */

export async function getWarpgateAdminRoles() {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/admin-roles`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch admin roles: ${response.status}`
    );
  }

  return response.json();
}

export async function deleteWarpgateAdminRole(roleId) {
  const response = await fetch(`${WARPGATE_ADMIN_API}/admin-roles/${roleId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`Failed to delete admin role: ${response.status}`);
  }
}

async function postWarpgateRole(path, payload, action) {
  const response = await fetch(`${WARPGATE_ADMIN_API}/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let reason = "";
    try {
      reason = await response.text();
    } catch {
      // Keep the HTTP status as the actionable error when there is no response body.
    }
    throw new Error(
      `${action} failed: HTTP ${response.status}${reason ? ` — ${reason}` : ""}`,
    );
  }

  return response.json();
}

export async function createWarpgateAccessRole({
  name,
  description = "",
  is_default = false,
}) {
  return postWarpgateRole(
    "roles",
    { name, description, is_default },
    "Creating access role",
  );
}

export async function createWarpgateAdminRole({
  name,
  description = "",
  ...permissions
}) {
  return postWarpgateRole(
    "admin-roles",
    { name, description, ...permissions },
    "Creating admin role",
  );
}


/* =========================================================
   TARGETS
========================================================= */

export async function getWarpgateTargets(search = "") {
  const query = search
    ? `?search=${encodeURIComponent(search)}`
    : "";

  const response = await fetch(
    `${WARPGATE_ADMIN_API}/targets${query}`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch targets: ${response.status}`
    );
  }

  return response.json();
}

export async function deleteWarpgateTarget(targetId) {
  const response = await fetch(`${WARPGATE_ADMIN_API}/targets/${targetId}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`Failed to delete target: ${response.status}`);
  }
}

export async function getAccessibleWarpgateTargets(search = "") {
  const query = search
    ? `?search=${encodeURIComponent(search)}`
    : "";
  const response = await fetch(
    `${WARPGATE_API}/targets${query}`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch accessible targets: ${response.status}`
    );
  }

  const targets = await response.json();
  if (!Array.isArray(targets)) {
    throw new Error("SecureAccess returned an invalid targets response.");
  }

  return targets.map((target) => ({
    ...target,
    options: {
      kind: target.kind,
      url: target.external_host || target.http_origin || "",
    },
  }));
}

export async function createWarpgateWebSshSession(targetId) {
  if (
    typeof targetId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(targetId)
  ) {
    throw new Error("The selected SSH target has an invalid identifier.");
  }

  const response = await fetch(`${WARPGATE_API}/web-ssh/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ target_id: targetId }),
  });
  if (!response.ok) {
    const messages = {
      401: "Your Warpgate session has expired. Sign in again.",
      403: "You are not authorized to connect to this SSH target.",
      404: "The selected SSH target is no longer available.",
      429: "The maximum number of active SSH sessions has been reached.",
    };
    throw new Error(
      messages[response.status] ||
        `Unable to create the SSH session: HTTP ${response.status}`,
    );
  }

  const result = await response.json();
  if (
    typeof result?.session_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      result.session_id,
    )
  ) {
    throw new Error("Warpgate returned an invalid SSH session identifier.");
  }
  return result.session_id;
}

export async function deleteWarpgateWebSshSession(sessionId) {
  if (
    typeof sessionId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)
  ) {
    throw new Error("The SSH session has an invalid identifier.");
  }

  const response = await fetch(
    `${WARPGATE_API}/web-ssh/sessions/${encodeURIComponent(sessionId)}`,
    {
      method: "DELETE",
      credentials: "include",
    },
  );
  if (!response.ok) {
    throw new Error(
      `Unable to close the SSH session: HTTP ${response.status}`,
    );
  }
}


/* =========================================================
   TARGET ROLES
========================================================= */

export async function getWarpgateTargetRoles(targetId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/targets/${targetId}/roles`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch target roles: ${response.status}`
    );
  }

  return response.json();
}


/* =========================================================
   SESSIONS
========================================================= */

export async function getWarpgateSessions({
  limit = 100,
  offset = 0,
  activeOnly = false,
  loggedInOnly = false,
} = {}) {
  const query = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    active_only: String(activeOnly),
    logged_in_only: String(loggedInOnly),
  });
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/sessions?${query.toString()}`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch sessions: ${response.status}`
    );
  }

  const data = await response.json();
  const sessions = Array.isArray(data)
    ? data
    : Array.isArray(data?.items)
      ? data.items
      : null;

  if (!sessions) {
    throw new Error("SecureAccess returned an invalid sessions response.");
  }

  const normalizedSessions = sessions.map((session) => ({
    ...session,
    target:
      typeof session.target === "string"
        ? session.target
        : session.target?.name || null,
  }));

  return Array.isArray(data)
    ? normalizedSessions
    : { ...data, items: normalizedSessions };
}

export async function getAllWarpgateSessions(applicationRole) {
  if (applicationRole === "admin") {
    const pageSize = 100;
    const firstPage = await getWarpgateSessions({ limit: pageSize });
    if (Array.isArray(firstPage)) {
      return firstPage;
    }

    const sessions = [...firstPage.items];
    const total = Number(firstPage.total) || sessions.length;
    for (let offset = sessions.length; offset < total; offset += pageSize * 5) {
      const offsets = [];
      for (
        let pageOffset = offset;
        pageOffset < Math.min(offset + pageSize * 5, total);
        pageOffset += pageSize
      ) {
        offsets.push(pageOffset);
      }
      const pages = await Promise.all(
        offsets.map((pageOffset) =>
          getWarpgateSessions({ limit: pageSize, offset: pageOffset }),
        ),
      );
      for (const page of pages) {
        sessions.push(...(Array.isArray(page) ? page : page.items));
      }
    }
    return { ...firstPage, items: sessions, total };
  }

  const response = await fetch("/@warpgate/rrweb/api/warpgate/sessions", {
    method: "GET",
    credentials: "include",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch scoped sessions: ${response.status}`);
  }
  const sessions = await response.json();
  if (!Array.isArray(sessions)) {
    throw new Error("SecureAccess returned an invalid sessions response.");
  }
  return sessions;
}

export async function getWarpgateRecordings({
  limit = 200,
  applicationRole = "admin",
} = {}) {
  const recordingsApi =
    applicationRole === "admin" ? WARPGATE_ADMIN_API : WARPGATE_API;
  const recordings = [];
  let offset = 0;
  let hasNextPage = true;

  while (hasNextPage) {
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    const response = await fetch(
      `${recordingsApi}/recordings?${query.toString()}`,
      {
        method: "GET",
        credentials: "include",
      }
    );

    if (
      applicationRole === "admin" &&
      response.status === 404 &&
      offset === 0
    ) {
      return getWarpgateRecordingsFromSessions();
    }
    if (!response.ok) {
      throw new Error(
        `Failed to fetch recordings from ${recordingsApi}/recordings: ${response.status} ${response.statusText}`.trim()
      );
    }

    const data = await response.json();
    if (Array.isArray(data)) {
      return data;
    }
    if (
      !Array.isArray(data?.items) ||
      !Number.isSafeInteger(data.total) ||
      data.total < 0 ||
      data.offset !== offset
    ) {
      throw new Error("SecureAccess returned an invalid recordings page.");
    }
    if (data.items.length === 0 && offset < data.total) {
      throw new Error("SecureAccess returned an incomplete recordings page.");
    }

    recordings.push(...data.items);
    offset += data.items.length;
    hasNextPage = offset < data.total;
  }

  return recordings;
}

async function getWarpgateRecordingsFromSessions() {
  const sessionsPage = await getAllWarpgateSessions("admin");
  const sessions = Array.isArray(sessionsPage)
    ? sessionsPage
    : sessionsPage.items;
  const recordings = [];

  for (let offset = 0; offset < sessions.length; offset += 8) {
    const sessionBatch = sessions.slice(offset, offset + 8);
    const batchRecordings = await Promise.all(
      sessionBatch.map(async (session) => {
        if (session.protocol && session.protocol.toUpperCase() !== "SSH") {
          return [];
        }
        const sessionRecordings = await getWarpgateSessionRecordings(session.id);
        if (!Array.isArray(sessionRecordings)) {
          throw new Error(
            `SecureAccess returned an invalid recordings response for session ${session.id}.`
          );
        }
        return sessionRecordings
          .filter((recording) =>
            String(recording.kind || "").toLowerCase() === "terminal"
          )
          .map((recording) => ({
            ...recording,
            sessionId: recording.session_id || session.id,
            username: session.username || null,
            target:
              typeof session.target === "string"
                ? session.target
                : session.target?.name || null,
            protocol: "SSH",
            recordingStatus: recording.ended
              ? "completed"
              : session.ended
                ? "incomplete"
                : "recording",
          }));
      }),
    );
    recordings.push(...batchRecordings.flat());
  }

  return recordings;
}

/* =========================================================
   AUDIT LOGS
========================================================= */
export async function getWarpgateSessionRecordings(sessionId) {
  const response = await fetch(
    `${WARPGATE_ADMIN_API}/sessions/${encodeURIComponent(
      sessionId
    )}/recordings`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch recordings for session ${sessionId}: ${response.status}`
    );
  }

  return response.json();
}


export async function getWarpgateLogs({
  search = "",
  username = "",
  target = "",
  limit = 100,
} = {}) {
  const query = new URLSearchParams({
    limit: String(limit),
    search,
    username,
    target,
  });

  const response = await fetch(
    `/@warpgate/rrweb/api/audit/warpgate-events?${query.toString()}`,
    {
      method: "GET",
      credentials: "include",
    }
  );
  if (!response.ok) {
    throw new Error(
      `Failed to fetch audit logs: HTTP ${response.status} ${response.statusText}`.trim()
    );
  }

  const events = await response.json();
  if (!Array.isArray(events)) {
    throw new Error("SecureAccess returned an invalid gateway log response.");
  }
  return events;
}