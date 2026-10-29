const assert = require("node:assert/strict");
const Database = require("better-sqlite3");
const test = require("node:test");

const {
  getAssignedApplicationRole,
  getUserAccessibleTargets,
  hasTargetRoleAssignment,
  isWarpgateSessionVisible,
  listVisibleWarpgateSessions,
  parseSessionTargetSnapshot,
} = require("../warpgate-rbac");

function createDatabase() {
  const db = new Database(":memory:");
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
    CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
    CREATE TABLE user_roles (
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      granted_at TEXT,
      expires_at TEXT,
      revoked_at TEXT
    );
    CREATE TABLE target_roles (
      target_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL
    );
    CREATE TABLE admin_roles (
      id INTEGER PRIMARY KEY,
      targets_create INTEGER NOT NULL DEFAULT 0,
      targets_edit INTEGER NOT NULL DEFAULT 0,
      targets_delete INTEGER NOT NULL DEFAULT 0,
      users_create INTEGER NOT NULL DEFAULT 0,
      users_edit INTEGER NOT NULL DEFAULT 0,
      users_delete INTEGER NOT NULL DEFAULT 0,
      access_roles_create INTEGER NOT NULL DEFAULT 0,
      access_roles_edit INTEGER NOT NULL DEFAULT 0,
      access_roles_delete INTEGER NOT NULL DEFAULT 0,
      access_roles_assign INTEGER NOT NULL DEFAULT 0,
      sessions_view INTEGER NOT NULL DEFAULT 0,
      sessions_terminate INTEGER NOT NULL DEFAULT 0,
      recordings_view INTEGER NOT NULL DEFAULT 0,
      tickets_create INTEGER NOT NULL DEFAULT 0,
      tickets_delete INTEGER NOT NULL DEFAULT 0,
      config_edit INTEGER NOT NULL DEFAULT 0,
      admin_roles_manage INTEGER NOT NULL DEFAULT 0,
      ticket_requests_manage INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE user_admin_roles (
      user_id INTEGER NOT NULL,
      admin_role_id INTEGER NOT NULL
    );
    CREATE TABLE secure_access_user_roles (
      user_id INTEGER PRIMARY KEY,
      application_role TEXT NOT NULL
    );
  `);
  return db;
}

test("honors any active Warpgate role assigned to the target, case-insensitively", () => {
  const db = createDatabase();
  db.exec(`
    INSERT INTO users VALUES (1, 'EngineerOne');
    INSERT INTO roles VALUES (1, 'engineer');
    INSERT INTO targets VALUES (1, 'web-prod');
    INSERT INTO user_roles VALUES (1, 1, NULL, NULL, NULL);
    INSERT INTO target_roles VALUES (1, 1);
  `);

  try {
    assert.equal(hasTargetRoleAssignment(db, "engineerone", "web-prod"), true);
    assert.equal(hasTargetRoleAssignment(db, "EngineerOne", "other-target"), false);
    assert.equal(hasTargetRoleAssignment(db, "missing-user", "web-prod"), false);
  } finally {
    db.close();
  }
});

test("rejects revoked, expired, and invalid-expiry target-role assignments", () => {
  const db = createDatabase();
  db.exec(`
    INSERT INTO users VALUES (1, 'developer');
    INSERT INTO roles VALUES (1, 'developer');
    INSERT INTO targets VALUES (1, 'web-prod');
    INSERT INTO user_roles VALUES (1, 1, NULL, NULL, '2026-01-01T00:00:00Z');
    INSERT INTO target_roles VALUES (1, 1);
  `);

  try {
    assert.equal(hasTargetRoleAssignment(db, "developer", "web-prod"), false);
    db.prepare("UPDATE user_roles SET revoked_at = NULL, expires_at = ?").run(
      new Date(Date.now() - 60_000).toISOString(),
    );
    assert.equal(hasTargetRoleAssignment(db, "developer", "web-prod"), false);
    db.prepare("UPDATE user_roles SET expires_at = ?").run("not-a-date");
    assert.equal(hasTargetRoleAssignment(db, "developer", "web-prod"), false);
  } finally {
    db.close();
  }
});

test("surfaces an RBAC database schema error instead of denying silently", () => {
  const db = new Database(":memory:");
  try {
    assert.throws(
      () => hasTargetRoleAssignment(db, "developer", "web-prod"),
      /no such table/,
    );
  } finally {
    db.close();
  }
});

test("defaults existing users to Developer and respects explicit application-role assignments", () => {
  const db = createDatabase();
  db.exec(`
    INSERT INTO users VALUES (1, 'Alice');
    INSERT INTO secure_access_user_roles VALUES (1, 'auditor_viewer');
  `);
  try {
    assert.equal(getAssignedApplicationRole(db, "alice"), "auditor_viewer");
    assert.equal(getAssignedApplicationRole(db, "missing-user"), "developer");
  } finally {
    db.close();
  }
});

test("derives Admin from the full Warpgate permission set, not access-role names", () => {
  const db = createDatabase();
  db.exec(`
    INSERT INTO users VALUES (1, 'AdminUser');
    INSERT INTO roles VALUES (1, 'admin');
    INSERT INTO admin_roles VALUES (
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
    );
    INSERT INTO user_admin_roles VALUES (1, 1);
    INSERT INTO secure_access_user_roles VALUES (1, 'auditor_viewer');
    INSERT INTO users VALUES (2, 'AccessRoleAdmin');
    INSERT INTO roles VALUES (2, 'admin');
  `);
  try {
    assert.equal(getAssignedApplicationRole(db, "adminuser"), "admin");
    assert.equal(getAssignedApplicationRole(db, "AccessRoleAdmin"), "developer");
  } finally {
    db.close();
  }
});

test("returns only target IDs with current, active Warpgate grants", () => {
  const db = createDatabase();
  db.exec(`
    INSERT INTO users VALUES (1, 'Alice');
    INSERT INTO roles VALUES (1, 'engineer');
    INSERT INTO roles VALUES (2, 'expired');
    INSERT INTO targets VALUES (1, 'prod');
    INSERT INTO targets VALUES (2, 'staging');
    INSERT INTO user_roles VALUES (1, 1, NULL, NULL, NULL);
    INSERT INTO user_roles VALUES (1, 2, NULL, '2020-01-01T00:00:00.000Z', NULL);
    INSERT INTO target_roles VALUES (1, 1);
    INSERT INTO target_roles VALUES (2, 2);
  `);
  try {
    assert.deepEqual(getUserAccessibleTargets(db, "alice"), [
      { id: 1, name: "prod" },
    ]);
  } finally {
    db.close();
  }
});

test("scopes Developer sessions to assignments while Auditors can view all known-owner sessions", () => {
  const session = {
    username: "Alice",
    target_snapshot: JSON.stringify({
      id: "target-web",
      name: "web-prod",
    }),
  };
  const assignedTargets = [{ id: "target-web", name: "web-prod" }];

  assert.equal(
    isWarpgateSessionVisible(session, "developer", "alice", assignedTargets),
    true,
  );
  assert.equal(
    isWarpgateSessionVisible(session, "developer", "bob", assignedTargets),
    false,
  );
  assert.equal(
    isWarpgateSessionVisible(session, "auditor_viewer", "auditor", assignedTargets),
    true,
  );
  assert.equal(
    isWarpgateSessionVisible(
      session,
      "auditor_viewer",
      "auditor",
      [],
    ),
    true,
  );
});

test("fails closed for unknown roles and malformed Warpgate session metadata", () => {
  const session = {
    username: "Alice",
    target_snapshot: "{bad json",
  };
  assert.equal(parseSessionTargetSnapshot(session.target_snapshot), null);
  assert.equal(
    isWarpgateSessionVisible(
      session,
      "developer",
      "alice",
      [{ id: "target-web", name: "web-prod" }],
    ),
    false,
  );
  assert.equal(
    isWarpgateSessionVisible(
      { ...session, username: "unknown" },
      "auditor_viewer",
      "auditor",
      [{ id: "target-web", name: "web-prod" }],
    ),
    false,
  );
  assert.equal(
    isWarpgateSessionVisible(
      { ...session, username: " unknown " },
      "auditor_viewer",
      "auditor",
      [],
    ),
    false,
  );
  assert.equal(
    isWarpgateSessionVisible(session, "unknown", "alice", []),
    false,
  );
});

test("lists only session rows authorized by the Warpgate session schema", () => {
  const db = new Database(":memory:");
  db.exec(`
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY,
      target_snapshot TEXT,
      username TEXT,
      started TEXT NOT NULL,
      ended TEXT,
      ticket_id TEXT,
      protocol TEXT NOT NULL,
      node_id TEXT NOT NULL
    );
  `);
  const insert = db.prepare(`
    INSERT INTO sessions
      (id, target_snapshot, username, started, protocol, node_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const targetSnapshot = (id, name) => JSON.stringify({ id, name });
  insert.run(
    "session-alice",
    targetSnapshot("target-web", "web-prod"),
    "Alice",
    "2026-10-20T10:00:00Z",
    "Http",
    "node-1",
  );
  insert.run(
    "session-bob",
    targetSnapshot("target-web", "web-prod"),
    "Bob",
    "2026-10-20T09:00:00Z",
    "Http",
    "node-1",
  );
  insert.run(
    "session-outside",
    targetSnapshot("target-other", "other"),
    "Bob",
    "2026-10-20T08:00:00Z",
    "Ssh",
    "node-1",
  );
  insert.run(
    "session-unknown",
    targetSnapshot("target-web", "web-prod"),
    null,
    "2026-10-20T07:00:00Z",
    "Http",
    "node-1",
  );

  try {
    const targets = [{ id: "target-web", name: "web-prod" }];
    const developerSessions = listVisibleWarpgateSessions(
      db,
      "developer",
      "alice",
      targets,
    );
    assert.deepEqual(
      developerSessions.map(({ id }) => id),
      ["session-alice"],
    );
    const auditorSessions = listVisibleWarpgateSessions(
      db,
      "auditor_viewer",
      "auditor",
      [],
    );
    assert.deepEqual(
      auditorSessions.map(({ id }) => id),
      ["session-alice", "session-bob", "session-outside"],
    );
    assert.equal(auditorSessions[0].target, "web-prod");
    assert.equal(auditorSessions[0].protocol, "Http");
  } finally {
    db.close();
  }
});
