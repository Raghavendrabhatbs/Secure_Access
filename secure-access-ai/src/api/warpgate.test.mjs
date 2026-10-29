import assert from "node:assert/strict";
import test from "node:test";

import {
  createWarpgateWebSshSession,
  createWarpgateAccessRole,
  createWarpgateAdminRole,
  deleteWarpgateWebSshSession,
  getAllWarpgateSessions,
  getAccessibleWarpgateTargets,
  getWarpgateAccessOrigin,
  getWarpgateRecordings,
  getWarpgateLogs,
  getWarpgateSessions,
  logoutFromWarpgate,
  normalizeWarpgateLogId,
  normalizeWarpgateLogTarget,
} from "./warpgate.js";

test("normalizes Warpgate Buffer UUIDs for stable audit row keys and session labels", () => {
  assert.equal(
    normalizeWarpgateLogId({
      type: "Buffer",
      data: Array.from({ length: 16 }, (_, index) => index),
    }),
    "00010203-0405-0607-0809-0a0b0c0d0e0f",
  );
  assert.equal(
    normalizeWarpgateLogId({ type: "Buffer", data: [1, 2, 3] }),
    null,
  );
});

test("replaces internal Warpgate module paths with the SecureAccess audit label", () => {
  assert.equal(
    normalizeWarpgateLogTarget("warpgate_common_http::logging"),
    "SecureAccess",
  );
  assert.equal(
    normalizeWarpgateLogTarget("warpgate_protocol_http::rrweb_proxy"),
    "SecureAccess",
  );
  assert.equal(normalizeWarpgateLogTarget("web-demo"), "web-demo");
  assert.equal(normalizeWarpgateLogTarget(null), null);
});

test("creates an SSH session for the selected target through Warpgate authorization", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(
      JSON.stringify({ session_id: "123e4567-e89b-42d3-a456-426614174000" }),
      { status: 201, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const sessionId = await createWarpgateWebSshSession(
      "123e4567-e89b-42d3-a456-426614174001",
    );
    assert.equal(sessionId, "123e4567-e89b-42d3-a456-426614174000");
    assert.equal(request.url, "/warpgate-api/web-ssh/sessions");
    assert.equal(request.options.method, "POST");
    assert.equal(request.options.credentials, "include");
    assert.deepEqual(JSON.parse(request.options.body), {
      target_id: "123e4567-e89b-42d3-a456-426614174001",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects malformed SSH target IDs without making a request", async () => {
  const originalFetch = globalThis.fetch;
  let requestCount = 0;
  globalThis.fetch = async () => {
    requestCount += 1;
    throw new Error("Unexpected request");
  };

  try {
    await assert.rejects(
      createWarpgateWebSshSession("../target"),
      /invalid identifier/,
    );
    assert.equal(requestCount, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("surfaces Warpgate authorization failures for SSH session creation", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(null, { status: 403 });

  try {
    await assert.rejects(
      createWarpgateWebSshSession("123e4567-e89b-42d3-a456-426614174001"),
      /not authorized/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("deletes only the requested Warpgate SSH session", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 204 });
  };

  try {
    await deleteWarpgateWebSshSession(
      "123e4567-e89b-42d3-a456-426614174000",
    );
    assert.equal(
      request.url,
      "/warpgate-api/web-ssh/sessions/123e4567-e89b-42d3-a456-426614174000",
    );
    assert.equal(request.options.method, "DELETE");
    assert.equal(request.options.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects malformed SSH session IDs without making a delete request", async () => {
  const originalFetch = globalThis.fetch;
  let requestCount = 0;
  globalThis.fetch = async () => {
    requestCount += 1;
    throw new Error("Unexpected request");
  };

  try {
    await assert.rejects(
      deleteWarpgateWebSshSession("../session"),
      /invalid identifier/,
    );
    assert.equal(requestCount, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("opens Warpgate on the same host so the authenticated session cookie is reused", () => {
  assert.equal(getWarpgateAccessOrigin("127.0.0.1"), "https://127.0.0.1:8888");
  assert.equal(getWarpgateAccessOrigin("localhost"), "https://localhost:8888");
  assert.throws(() => getWarpgateAccessOrigin(""), /hostname is required/);
});

test("creates an access role through Warpgate without navigation", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ id: "role-1", name: "operators" }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const role = await createWarpgateAccessRole({
      name: "operators",
      description: "Ops team",
      is_default: true,
    });
    assert.equal(role.name, "operators");
    assert.equal(request.url, "/warpgate-admin-api/roles");
    assert.equal(request.options.method, "POST");
    assert.equal(request.options.credentials, "include");
    assert.deepEqual(JSON.parse(request.options.body), {
      name: "operators",
      description: "Ops team",
      is_default: true,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("creates an admin role with explicit permission flags", async () => {
  const originalFetch = globalThis.fetch;
  let requestBody;
  globalThis.fetch = async (_url, options) => {
    requestBody = JSON.parse(options.body);
    return new Response(JSON.stringify({ id: "admin-role-1" }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    await createWarpgateAdminRole({
      name: "auditors",
      description: "",
      recordings_view: true,
      users_create: false,
    });
    assert.deepEqual(requestBody, {
      name: "auditors",
      description: "",
      recordings_view: true,
      users_create: false,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads target-scoped targets through the authenticated Warpgate API", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl;
  let requestOptions;
  globalThis.fetch = async (url, options) => {
    requestedUrl = url;
    requestOptions = options;
    return new Response(
      JSON.stringify([
        {
          id: "target-1",
          name: "web-prod",
          kind: "http",
          http_origin: "https://gateway.example/target-1",
          external_host: "app.example",
        },
      ]),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const targets = await getAccessibleWarpgateTargets();
    assert.equal(requestedUrl, "/warpgate-api/targets");
    assert.equal(requestOptions.credentials, "include");
    assert.equal(targets[0].options.kind, "http");
    assert.equal(targets[0].options.url, "app.example");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects malformed target-scoped responses", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ items: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  try {
    await assert.rejects(
      getAccessibleWarpgateTargets(),
      /invalid targets response/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("normalizes paginated session targets for frontend consumers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        items: [
          {
            id: "session-1",
            target: { name: "web-prod", options: { kind: "http" } },
          },
        ],
        offset: 0,
        total: 1,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );

  try {
    const result = await getWarpgateSessions();
    assert.equal(result.items[0].target, "web-prod");
    assert.equal(result.total, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads every page when dashboard session totals exceed the first page", async () => {
  const originalFetch = globalThis.fetch;
  const requestedOffsets = [];
  globalThis.fetch = async (url) => {
    const parsed = new URL(url, "http://localhost");
    const offset = Number(parsed.searchParams.get("offset"));
    requestedOffsets.push(offset);
    const items = Array.from(
      { length: Math.min(100, Math.max(0, 201 - offset)) },
      (_, index) => ({
        id: `session-${offset + index}`,
        target: { name: "web-prod" },
      }),
    );
    return new Response(
      JSON.stringify({ items, offset, total: 201 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const result = await getAllWarpgateSessions("admin");
    assert.equal(result.items.length, 201);
    assert.deepEqual(requestedOffsets.sort((a, b) => a - b), [0, 100, 200]);
    assert.equal(result.items[200].target, "web-prod");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("logs out through Warpgate using the authenticated browser session", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 200 });
  };

  try {
    await logoutFromWarpgate();
    assert.equal(request.url, "/warpgate-api/auth/logout");
    assert.equal(request.options.method, "POST");
    assert.equal(request.options.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads non-admin sessions through the target-scoped rrweb endpoint", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl;
  globalThis.fetch = async (url) => {
    requestedUrl = url;
    return new Response(
      JSON.stringify([{ id: "session-scoped", target: "prod" }]),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const result = await getAllWarpgateSessions("auditor_viewer");
    assert.equal(requestedUrl, "/@warpgate/rrweb/api/warpgate/sessions");
    assert.equal(result[0].id, "session-scoped");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads every paginated Warpgate recording page", async () => {
  const originalFetch = globalThis.fetch;
  const requestedOffsets = [];
  globalThis.fetch = async (url) => {
    const parsed = new URL(url, "http://localhost");
    const offset = Number(parsed.searchParams.get("offset"));
    requestedOffsets.push(offset);
    const items = offset === 0
      ? [{ id: "recording-1" }, { id: "recording-2" }]
      : [{ id: "recording-3" }];
    return new Response(
      JSON.stringify({ items, offset, total: 3 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const recordings = await getWarpgateRecordings({ limit: 2 });
    assert.deepEqual(recordings.map(({ id }) => id), [
      "recording-1",
      "recording-2",
      "recording-3",
    ]);
    assert.deepEqual(requestedOffsets, [0, 2]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads non-admin SSH recordings through the authenticated scoped API", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl;
  let requestOptions;
  globalThis.fetch = async (url, options) => {
    requestedUrl = url;
    requestOptions = options;
    return new Response(
      JSON.stringify({
        items: [],
        offset: 0,
        total: 0,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const recordings = await getWarpgateRecordings({
      applicationRole: "auditor_viewer",
    });
    assert.deepEqual(recordings, []);
    assert.equal(requestedUrl, "/warpgate-api/recordings?limit=200&offset=0");
    assert.equal(requestOptions.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads Admin audit logs through the authenticated gateway audit endpoint", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify([{ id: "gateway-log-1" }]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const events = await getWarpgateLogs({ limit: 500, applicationRole: "admin" });
    assert.equal(events[0].id, "gateway-log-1");
    assert.equal(requests.length, 1);
    assert.equal(
      requests[0].url,
      "/@warpgate/rrweb/api/audit/warpgate-events?limit=500&search=&username=&target=",
    );
    assert.equal(requests[0].options.method, "GET");
    assert.equal(requests[0].options.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads Auditor audit logs through the same authenticated gateway audit endpoint", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify([{ id: "gateway-log-1" }]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const events = await getWarpgateLogs({
      limit: 500,
      applicationRole: "auditor_viewer",
    });
    assert.equal(events[0].id, "gateway-log-1");
    assert.deepEqual(
      requests.map(({ url }) => url),
      [
        "/@warpgate/rrweb/api/audit/warpgate-events?limit=500&search=&username=&target=",
      ],
    );
    assert.equal(requests[0].options.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("does not return stale audit data when the gateway audit API fails", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url) => {
    requests.push(url);
    return new Response("unavailable", { status: 503, statusText: "Unavailable" });
  };

  try {
    await assert.rejects(getWarpgateLogs({ limit: 500 }), /HTTP 503/);
    assert.deepEqual(
      requests,
      [
        "/@warpgate/rrweb/api/audit/warpgate-events?limit=500&search=&username=&target=",
      ],
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects an incomplete Warpgate recordings page instead of returning partial data", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({ items: [], offset: 0, total: 2 }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );

  try {
    await assert.rejects(
      getWarpgateRecordings(),
      /incomplete recordings page/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("falls back to authorized per-session recordings when the global route is not deployed", async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url) => {
    const parsed = new URL(url, "http://localhost");
    requests.push(parsed.pathname);
    if (parsed.pathname.endsWith("/sessions")) {
      return new Response(
        JSON.stringify({
          items: [
            {
              id: "ssh-session-1",
              protocol: "SSH",
              username: "operator",
              target: { name: "prod-shell" },
              ended: "2026-10-19T10:01:00Z",
            },
            {
              id: "web-session-1",
              protocol: "HTTP",
              username: "operator",
              target: { name: "web-app" },
            },
          ],
          offset: 0,
          total: 2,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (parsed.pathname.endsWith("/sessions/ssh-session-1/recordings")) {
      return new Response(
        JSON.stringify([
          {
            id: "terminal-recording",
            session_id: "ssh-session-1",
            kind: "Terminal",
            ended: "2026-10-19T10:01:00Z",
          },
          {
            id: "traffic-recording",
            session_id: "ssh-session-1",
            kind: "Traffic",
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (parsed.pathname.endsWith("/recordings")) {
      return new Response("not found", { status: 404 });
    }
    throw new Error(`Unexpected request: ${parsed.pathname}`);
  };

  try {
    const recordings = await getWarpgateRecordings();
    assert.equal(recordings.length, 1);
    assert.equal(recordings[0].id, "terminal-recording");
    assert.equal(recordings[0].username, "operator");
    assert.equal(recordings[0].target, "prod-shell");
    assert.equal(recordings[0].recordingStatus, "completed");
    assert.deepEqual(requests, [
      "/warpgate-admin-api/recordings",
      "/warpgate-admin-api/sessions",
      "/warpgate-admin-api/sessions/ssh-session-1/recordings",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
