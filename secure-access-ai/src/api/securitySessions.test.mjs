import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  getLiveWarpgateSessions,
  terminateLiveWarpgateSession,
} from "./securitySessions.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("loads active sessions through the application backend with cookies", async () => {
  const sessions = [{ id: "session-1" }];
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "/ai-api/admin/warpgate/sessions/active");
    assert.equal(options.credentials, "include");
    return new Response(JSON.stringify({ sessions }), { status: 200 });
  };

  assert.deepEqual(await getLiveWarpgateSessions(), sessions);
});

test("termination posts the selected session ID and operator reason", async () => {
  const sessionId = "94e34c21-156c-4a41-9cf2-ccedc1520669";
  globalThis.fetch = async (url, options) => {
    assert.equal(
      url,
      `/ai-api/admin/warpgate/sessions/${sessionId}/terminate`,
    );
    assert.equal(options.method, "POST");
    assert.deepEqual(JSON.parse(options.body), { reason: "operator test" });
    return new Response(
      JSON.stringify({
        status: "confirmed",
        session: { id: sessionId, ended: "2026-10-25T00:00:00Z" },
      }),
      { status: 200 },
    );
  };

  const result = await terminateLiveWarpgateSession(sessionId, "operator test");
  assert.equal(result.status, "confirmed");
});

test("rejects an invalid session ID before making a request", async () => {
  let requested = false;
  globalThis.fetch = async () => {
    requested = true;
    return new Response("{}", { status: 200 });
  };

  await assert.rejects(
    terminateLiveWarpgateSession("not-a-session", "operator test"),
    /invalid identifier/,
  );
  assert.equal(requested, false);
});

test("preserves backend failure details", async () => {
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "Warpgate is unavailable." }), {
      status: 503,
    });

  await assert.rejects(getLiveWarpgateSessions(), /Warpgate is unavailable/);
});
