import assert from "node:assert/strict";
import test from "node:test";

import {
  getSecureAccessAuditEvents,
  logSecureAccessEvent,
} from "./audit.js";

test("submits a Secure Access audit event without client identity", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ success: true }), { status: 201 });
  };

  try {
    await logSecureAccessEvent("access", "ssh.target.opened", {
      target: "production",
    });
    assert.equal(request.url, "/@warpgate/rrweb/api/audit/events");
    assert.equal(request.options.method, "POST");
    assert.equal(request.options.credentials, "include");
    assert.deepEqual(JSON.parse(request.options.body), {
      category: "access",
      action: "ssh.target.opened",
      details: { target: "production" },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("loads Secure Access audit events with a bounded query", async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  globalThis.fetch = async (url) => {
    requestUrl = url;
    return new Response(JSON.stringify([{ id: "event-1" }]), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const events = await getSecureAccessAuditEvents({
      limit: 500,
      search: "page viewed",
    });
    assert.equal(events[0].id, "event-1");
    assert.equal(
      requestUrl,
      "/@warpgate/rrweb/api/audit/events?limit=500&search=page+viewed",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects invalid Secure Access audit event responses", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ events: [] }));

  try {
    await assert.rejects(
      getSecureAccessAuditEvents(),
      /invalid audit events response/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
