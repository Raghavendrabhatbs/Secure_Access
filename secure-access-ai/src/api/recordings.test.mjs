import assert from "node:assert/strict";
import test from "node:test";

import {
  canReplayRecording,
  getRrwebRecording,
  validateRrwebEvents,
} from "./recordings.js";

const validEvents = [
  {
    type: 4,
    timestamp: 1000,
    data: { href: "https://example.test", width: 1280, height: 720 },
  },
  {
    type: 2,
    timestamp: 1010,
    data: { node: { type: 0, childNodes: [] }, initialOffset: { left: 0, top: 0 } },
  },
];

test("accepts a valid rrweb stream containing a full snapshot", () => {
  assert.equal(validateRrwebEvents(validEvents), validEvents);
});

test("allows legacy recording entries without availability metadata to be replayed", () => {
  assert.equal(
    canReplayRecording({
      file: "session-legacy-recording.json",
      eventCount: 12,
    }),
    true,
  );
  assert.equal(
    canReplayRecording({
      sessionId: "session-no-file",
      eventCount: 12,
      hasRecording: false,
    }),
    false,
  );
  assert.equal(
    canReplayRecording({
      sessionId: "session-too-short",
      eventCount: 1,
    }),
    false,
  );
  assert.equal(
    canReplayRecording({
      sessionId: "../bad-id",
      eventCount: 12,
    }),
    false,
  );
});

test("rejects empty, undersized, malformed, and snapshot-free recordings", () => {
  assert.throws(() => validateRrwebEvents([]), /too few events/);
  assert.throws(() => validateRrwebEvents([validEvents[0]]), /too few events/);
  assert.throws(
    () => validateRrwebEvents([validEvents[0], { type: 2, timestamp: 1, data: [] }]),
    /invalid rrweb events/,
  );
  assert.throws(
    () => validateRrwebEvents([
      validEvents[0],
      { type: 3, timestamp: 1010, data: { source: 0 } },
    ]),
    /no full snapshot/,
  );
});

test("loads the file derived from the selected session ID", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl;
  let requestOptions;
  globalThis.fetch = async (url, options) => {
    requestedUrl = url;
    requestOptions = options;
    return new Response(JSON.stringify(validEvents), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const events = await getRrwebRecording("session-test_123");
    assert.deepEqual(events, validEvents);
    assert.equal(
      requestedUrl,
      "/@warpgate/rrweb/api/sessions/session-test_123.json",
    );
    assert.equal(requestOptions.credentials, "include");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects invalid session IDs before making a recording request", async () => {
  await assert.rejects(
    getRrwebRecording("../outside"),
    /invalid session ID/,
  );
});
