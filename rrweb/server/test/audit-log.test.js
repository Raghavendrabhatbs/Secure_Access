const assert = require("node:assert/strict");
const test = require("node:test");
const Database = require("better-sqlite3");

const {
  initializeAuditStore,
  insertAuditEvent,
  listAuditEvents,
  normalizeAuditEvent,
} = require("../audit-log");

test("normalizes audit events using the authenticated actor and redacts secrets", () => {
  const timestamp = new Date("2026-10-20T08:00:00.000Z");
  const event = normalizeAuditEvent(
    {
      category: "access",
      action: "target.opened",
      details: {
        target: "prod-shell",
        sessionId: "session-123",
        password: "must-not-be-stored",
        note: "Target opened",
      },
      username: "spoofed-user",
      timestamp: "2000-01-01T00:00:00.000Z",
    },
    "authenticated-user",
    timestamp,
  );

  assert.ok(event);
  assert.equal(event.username, "authenticated-user");
  assert.equal(event.timestamp, timestamp.toISOString());
  assert.equal(event.target, "prod-shell");
  assert.equal(event.sessionId, "session-123");
  assert.deepEqual(JSON.parse(event.detailsJson), {
    target: "prod-shell",
    sessionId: "session-123",
    note: "Target opened",
  });
});

test("rejects malformed audit events and unsafe detail values", () => {
  assert.equal(
    normalizeAuditEvent({ category: "Bad category", action: "submitted" }, "alice"),
    null,
  );
  assert.equal(
    normalizeAuditEvent({
      category: "ui",
      action: "control.clicked",
      details: { content: { password: "secret" } },
    }, "alice"),
    null,
  );
});

test("persists and searches audit events with a bounded result limit", () => {
  const database = new Database(":memory:");
  initializeAuditStore(database);
  try {
    const first = normalizeAuditEvent({
      category: "access",
      action: "target.opened",
      details: { target: "prod-shell" },
    }, "alice", new Date("2026-10-20T07:00:00.000Z"));
    const second = normalizeAuditEvent({
      category: "navigation",
      action: "page.viewed",
      details: { route: "/admin/users" },
    }, "bob", new Date("2026-10-20T08:00:00.000Z"));

    insertAuditEvent(database, first);
    insertAuditEvent(database, second);

    assert.equal(listAuditEvents(database, { search: "prod-shell" }).length, 1);
    assert.equal(listAuditEvents(database, { limit: 0 }).length, 1);
    assert.equal(listAuditEvents(database, { limit: 5000 }).length, 2);
    assert.equal(listAuditEvents(database)[0].username, "bob");
    assert.deepEqual(listAuditEvents(database)[0].details, {
      route: "/admin/users",
    });
  } finally {
    database.close();
  }
});

test("returns audit events from all users when called without a scope filter", () => {
  const database = new Database(":memory:");
  initializeAuditStore(database);
  try {
    for (const [username, target] of [
      ["alice", "prod-shell"],
      ["bob", "prod-shell"],
      ["bob", "dev-shell"],
    ]) {
      const event = normalizeAuditEvent(
        {
          category: "access",
          action: "target.opened",
          details: { target },
        },
        username,
      );
      insertAuditEvent(database, event);
    }

    assert.deepEqual(
      listAuditEvents(database).map((event) => event.username).sort(),
      ["alice", "bob", "bob"],
    );
  } finally {
    database.close();
  }
});
