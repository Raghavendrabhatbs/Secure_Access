const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  appendIdempotentBatch,
  appendRecordingFailure,
  authorizeRecordingToken,
  canControlRecordingByPolicy,
  canWriteRecordingByApplicationRole,
  canViewRecordingByPolicy,
  canWatchActiveWebRecording,
  hasActiveTargetRoleAssignment,
  getRecordingLifecycleStatus,
  isRecordingFinalized,
  isActiveRoleAssignment,
  isValidEventBatch,
  isValidRecordingFailure,
  isValidSessionId,
  isValidVisitId,
  recordingIdentityMatchesMetadata,
  redactPageUrl,
  verifyRecordingToken,
} = require("../recording-utils");

const signingSecret = "test-signing-secret-with-at-least-32-bytes";

function sign(payload) {
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    "base64url",
  );
  const signature = crypto
    .createHmac("sha256", signingSecret)
    .update(encodedPayload)
    .digest("base64url");
  return `${encodedPayload}.${signature}`;
}

test("accepts signed, unexpired tokens bound to a recording session", () => {
  const payload = {
    username: "alice",
    target: "web",
    authenticationType: "user",
    warpgateUserId: "user-id-a",
    warpgateSessionId: "warpgate-session-a",
    recordingSessionId: "session-12345678",
    expiresAt: Date.now() + 60_000,
  };

  assert.deepEqual(
    verifyRecordingToken(sign(payload), signingSecret),
    payload,
  );
  assert.equal(
    verifyRecordingToken(
      sign(payload),
      "different-signing-secret-32-bytes",
    ),
    null,
  );
});

test("allows Watch only for an Admin and the bound active web session", () => {
  const metadata = {
    sessionId: "session-watch123",
    warpgateSessionId: "warpgate-session-a",
    warpgateUserId: "user-id-a",
    username: "alice",
    target: "web",
    recordingStatus: "recording",
  };
  const warpgateSession = {
    id: "warpgate-session-a",
    username: "Alice",
    protocol: "HTTPS",
    ended: null,
    target_snapshot: JSON.stringify({ id: "target-id", name: "web" }),
  };

  assert.equal(
    canWatchActiveWebRecording(
      "admin",
      metadata.sessionId,
      metadata,
      warpgateSession,
      "user-id-a",
      true,
    ),
    true,
  );
  for (const role of ["developer", "auditor_viewer", undefined]) {
    assert.equal(
      canWatchActiveWebRecording(
        role,
        metadata.sessionId,
        metadata,
        warpgateSession,
        "user-id-a",
        true,
      ),
      false,
    );
  }
  assert.equal(
    canWatchActiveWebRecording(
      "admin",
      metadata.sessionId,
      metadata,
      { ...warpgateSession, ended: "2026-10-21T00:00:00Z" },
      "user-id-a",
      true,
    ),
    false,
  );
  assert.equal(
    canWatchActiveWebRecording(
      "admin",
      metadata.sessionId,
      warpgateSession,
      warpgateSession,
      "different-user",
      true,
    ),
    false,
  );
  assert.equal(
    canWatchActiveWebRecording(
      "admin",
      metadata.sessionId,
      metadata,
      warpgateSession,
      "user-id-a",
      false,
    ),
    false,
  );
});

test("derives recording lifecycle from persisted state and recent activity", () => {
  const now = Date.parse("2026-10-19T12:00:00.000Z");
  const recent = new Date(now - 30_000).toISOString();
  const stale = new Date(now - 91_000).toISOString();

  assert.equal(
    getRecordingLifecycleStatus(
      { recordingStatus: "starting", lastSeenAt: recent, eventCount: 0 },
      true,
      now,
    ),
    "recording",
  );
  assert.equal(
    getRecordingLifecycleStatus(
      { recordingStatus: "recording", lastSeenAt: recent, eventCount: 12 },
      true,
      now,
    ),
    "recording",
  );
  assert.equal(
    getRecordingLifecycleStatus(
      { recordingStatus: "recording", lastSeenAt: stale, eventCount: 12 },
      true,
      now,
    ),
    "stopped",
  );
  assert.equal(
    getRecordingLifecycleStatus(
      { recordingStatus: "stopped", stoppedAt: recent },
      false,
      now,
    ),
    "stopped",
  );
  assert.equal(
    getRecordingLifecycleStatus(
      { recordingStatus: "recording", lastSeenAt: recent },
      false,
      now,
    ),
    "stopped",
  );
  assert.equal(
    getRecordingLifecycleStatus({ eventCount: 12 }, false, now),
    "stopped",
  );
});

test("finalizes replay after an explicit stop without waiting for the Warpgate session row", () => {
  const stoppedMetadata = {
    recordingStatus: "stopped",
    stoppedAt: "2026-10-21T13:23:55.335Z",
  };
  assert.equal(isRecordingFinalized(stoppedMetadata, false, true), true);
  assert.equal(isRecordingFinalized(stoppedMetadata, true, true), false);
  assert.equal(isRecordingFinalized(stoppedMetadata, false, false), false);
  assert.equal(
    isRecordingFinalized(
      { recordingStatus: "recording" },
      false,
      true,
    ),
    false,
  );
});

test("validates and deduplicates bounded recording failure diagnostics", () => {
  assert.equal(isValidRecordingFailure("upload", 503), true);
  assert.equal(isValidRecordingFailure("heartbeat", null), true);
  assert.equal(isValidRecordingFailure("other", 503), false);
  assert.equal(isValidRecordingFailure("upload", 99), false);
  assert.equal(isValidRecordingFailure("upload", 600), false);

  const metadata = {};
  const firstTime = new Date("2026-10-19T12:00:00.000Z");
  assert.equal(appendRecordingFailure(metadata, "upload", 503, firstTime), false);
  assert.equal(
    appendRecordingFailure(
      metadata,
      "upload",
      503,
      new Date(firstTime.getTime() + 30_000),
    ),
    true,
  );
  assert.equal(metadata.recordingFailures.length, 1);
  assert.equal(metadata.lastFailure.httpStatus, 503);
  assert.equal(metadata.lastFailure.message, "Recording upload request failed with HTTP 503");
  metadata.lastFailure.resolvedAt = new Date(
    firstTime.getTime() + 40_000,
  ).toISOString();
  assert.equal(
    appendRecordingFailure(
      metadata,
      "upload",
      503,
      new Date(firstTime.getTime() + 45_000),
    ),
    false,
  );
  assert.equal(metadata.recordingFailures.length, 2);

  for (let index = 0; index < 25; index += 1) {
    appendRecordingFailure(
      metadata,
      "start",
      502,
      new Date(firstTime.getTime() + 60_000 + index * 60_000),
    );
  }
  assert.equal(metadata.recordingFailures.length, 20);
});

test("rejects tampered, expired, and unbound tokens", () => {
  const basePayload = {
    username: "alice",
    warpgateUserId: "user-id-a",
    target: "web",
    recordingSessionId: "session-12345678",
    expiresAt: Date.now() + 60_000,
  };

  assert.equal(verifyRecordingToken(`${sign(basePayload)}x`, signingSecret), null);
  assert.equal(
    verifyRecordingToken(
      sign({ ...basePayload, expiresAt: Date.now() - 1 }),
      signingSecret,
    ),
    null,
  );
  assert.equal(verifyRecordingToken(sign(basePayload), ""), null);
  const { recordingSessionId, ...unboundPayload } = basePayload;
  assert.equal(verifyRecordingToken(sign(unboundPayload), signingSecret), null);
});

test("authorizes valid recording tokens against current recording permissions", () => {
  const token = sign({
    username: "alice",
    target: "web",
    authenticationType: "user",
    warpgateUserId: "user-id-a",
    recordingSessionId: "session-12345678",
    expiresAt: Date.now() + 60_000,
  });
  const allowAlice = (username, target) =>
    username === "alice" && target === "web";

  const authorized = authorizeRecordingToken(
    `Bearer ${token}`,
    signingSecret,
    allowAlice,
  );
  assert.equal(authorized.statusCode, 200);
  assert.equal(authorized.identity.username, "alice");
  assert.equal(authorized.identity.target, "web");
  assert.equal(
    authorizeRecordingToken("", signingSecret, allowAlice).statusCode,
    401,
  );
  assert.equal(
    authorizeRecordingToken("Bearer invalid", signingSecret, allowAlice)
      .statusCode,
    401,
  );
  const denied = authorizeRecordingToken(
    `Bearer ${token}`,
    signingSecret,
    () => false,
  );
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.identity, undefined);
});

test("accepts Warpgate user and ticket tokens without a second RBAC database check", () => {
  assert.equal(
    canControlRecordingByPolicy(
      "alice",
      "web",
      "ticket",
    ),
    true,
  );
  assert.equal(
    canControlRecordingByPolicy(
      "alice",
      "web",
      "user",
    ),
    true,
  );
  assert.equal(
    canControlRecordingByPolicy(
      "alice",
      "web",
      "unknown",
    ),
    false,
  );
  assert.equal(
    canControlRecordingByPolicy(
      " alice ",
      " web ",
      "ticket",
    ),
    true,
  );
  assert.equal(
    canControlRecordingByPolicy(
      " unknown ",
      " web ",
      "ticket",
    ),
    false,
  );

  const ticketToken = sign({
    username: "alice",
    target: "web",
    authenticationType: "ticket",
    recordingSessionId: "session-12345678",
    expiresAt: Date.now() + 60_000,
  });
  const authorized = authorizeRecordingToken(
    `Bearer ${ticketToken}`,
    signingSecret,
    canControlRecordingByPolicy,
  );
  assert.equal(authorized.statusCode, 200);
  assert.equal(authorized.identity.authenticationType, "ticket");

  const userToken = sign({
    username: "alice",
    target: "web",
    authenticationType: "user",
    recordingSessionId: "session-12345678",
    expiresAt: Date.now() + 60_000,
  });
  assert.equal(
    authorizeRecordingToken(
      `Bearer ${userToken}`,
      signingSecret,
      canControlRecordingByPolicy,
    ).statusCode,
    200,
  );
});

test("accepts any active Warpgate target role and rejects expired or revoked assignments", () => {
  assert.equal(
    hasActiveTargetRoleAssignment([
      {
        role: "engineer",
        granted_at: new Date().toISOString(),
        expires_at: null,
        revoked_at: null,
      },
    ]),
    true,
  );
  assert.equal(hasActiveTargetRoleAssignment([]), false);
  assert.equal(
    isActiveRoleAssignment({
      expires_at: new Date(Date.now() - 1000).toISOString(),
      revoked_at: null,
    }),
    false,
  );
  assert.equal(
    isActiveRoleAssignment({
      expires_at: "not-a-date",
      revoked_at: null,
    }),
    false,
  );
  assert.equal(
    isActiveRoleAssignment({
      expires_at: null,
      revoked_at: "2026-01-01T00:00:00Z",
    }),
    false,
  );
});

test("limits developer recordings to their assigned target scope and gives auditors read-only access to all", () => {
  const metadata = {
    username: "Alice",
    target: "web-prod",
    targets: ["web-prod"],
  };
  const authorizedTargets = ["web-prod"];

  assert.equal(
    canViewRecordingByPolicy(
      "alice",
      "developer",
      metadata,
      authorizedTargets,
    ),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy(
      "bob",
      "developer",
      metadata,
      authorizedTargets,
    ),
    false,
  );
  assert.equal(
    canViewRecordingByPolicy(
      "bob",
      "auditor_viewer",
      metadata,
      authorizedTargets,
    ),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy("bob", "auditor_viewer", metadata, []),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy("bob", "auditor_viewer", { username: "Alice" }, []),
    false,
  );
  assert.equal(
    canViewRecordingByPolicy(
      "bob",
      "auditor_viewer",
      { username: "Alice", target: "unassigned-target" },
      [],
    ),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy(
      "bob",
      "auditor_viewer",
      { username: " unknown ", target: "unassigned-target" },
      [],
    ),
    false,
  );
  assert.equal(
    canViewRecordingByPolicy(
      " alice ",
      "developer",
      { username: "Alice", target: "web-prod", targets: ["web-prod"] },
      [" web-prod "],
    ),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy("bob", "admin", metadata),
    true,
  );
  assert.equal(
    canViewRecordingByPolicy("bob", "unknown", metadata),
    false,
  );
});

test("allows recording writes only for Admin and Developer application roles", () => {
  assert.equal(canWriteRecordingByApplicationRole("admin"), true);
  assert.equal(canWriteRecordingByApplicationRole("developer"), true);
  assert.equal(canWriteRecordingByApplicationRole("auditor_viewer"), false);
  assert.equal(canWriteRecordingByApplicationRole("unknown"), false);
});

test("rejects invalid rrweb event batches", () => {
  const validEvent = {
    type: 2,
    timestamp: Date.now(),
    data: { node: { type: 0 } },
  };
  assert.equal(
    isValidEventBatch({
      batchId: "batch-12345678",
      events: [validEvent],
    }),
    true,
  );
  assert.equal(
    isValidEventBatch({
      batchId: "short",
      events: [validEvent],
    }),
    false,
  );
  assert.equal(
    isValidEventBatch({
      batchId: "batch-12345678",
      events: [],
    }),
    false,
  );
  assert.equal(
    isValidEventBatch({
      batchId: "batch-12345678",
      events: [{ type: "snapshot", timestamp: NaN, data: [] }],
    }),
    false,
  );
});

test("binds persisted recordings to the token identity, target, and session", () => {
  const identity = {
    username: "alice",
    target: "web",
    authenticationType: "user",
    recordingSessionId: "session-12345678",
  };
  const metadata = {
    username: "alice",
    authenticationType: "user",
    target: "web",
    warpgateUserId: "user-id-a",
    warpgateSessionId: "warpgate-session-a",
    targets: ["web", "docs"],
  };
  const boundIdentity = {
    ...identity,
    warpgateUserId: "user-id-a",
    warpgateSessionId: "warpgate-session-a",
  };

  assert.equal(
    recordingIdentityMatchesMetadata(
      boundIdentity,
      metadata,
      "session-12345678",
    ),
    true,
  );
  assert.equal(
    recordingIdentityMatchesMetadata(
      { ...boundIdentity, target: "docs" },
      metadata,
      "session-12345678",
    ),
    false,
  );
  assert.equal(
    recordingIdentityMatchesMetadata(
      { ...boundIdentity, warpgateUserId: "user-id-b" },
      metadata,
      "session-12345678",
    ),
    false,
  );
  assert.equal(
    recordingIdentityMatchesMetadata(
      { ...boundIdentity, warpgateSessionId: "warpgate-session-b" },
      metadata,
      "session-12345678",
    ),
    false,
  );
  assert.equal(
    recordingIdentityMatchesMetadata(
      boundIdentity,
      metadata,
      "session-other",
    ),
    false,
  );
});

test("validates identifiers and removes sensitive or gateway routing data from URLs", () => {
  assert.equal(isValidSessionId("session-123_ab"), true);
  assert.equal(isValidSessionId("../session-123"), false);
  assert.equal(isValidVisitId("visit-12345678"), true);
  assert.equal(isValidVisitId("short"), false);

  assert.equal(
    redactPageUrl(
      "https://example.test/path?tab=overview&access_token=secret&warpgate-target=web#section",
    ),
    "https://example.test/path?tab=overview&access_token=%5Bredacted%5D",
  );
  assert.equal(redactPageUrl("not a URL"), null);
});

test("event batch retries are idempotent", () => {
  const events = [{ type: 3 }];
  const sessionEvents = [];
  const metadata = { batchIds: [] };

  assert.equal(
    appendIdempotentBatch(sessionEvents, metadata, "batch-12345678", events),
    true,
  );
  assert.equal(
    appendIdempotentBatch(sessionEvents, metadata, "batch-12345678", events),
    false,
  );
  assert.equal(sessionEvents.length, 1);
  assert.equal(metadata.eventCount, 1);
});
