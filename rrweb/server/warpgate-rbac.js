const { hasActiveTargetRoleAssignment } = require("./recording-utils");

function hasTargetRoleAssignment(db, username, targetName) {
  if (
    !db ||
    typeof username !== "string" ||
    username.length === 0 ||
    typeof targetName !== "string" ||
    targetName.length === 0
  ) {
    return false;
  }

  const assignments = db
    .prepare(`
      SELECT
        r.name AS role,
        ur.granted_at,
        ur.expires_at,
        ur.revoked_at
      FROM users u
      JOIN user_roles ur
        ON ur.user_id = u.id
      JOIN roles r
        ON r.id = ur.role_id
      JOIN target_roles tr
        ON tr.role_id = r.id
      JOIN targets t
        ON t.id = tr.target_id
      WHERE lower(u.username) = lower(?)
        AND t.name = ?
    `)
    .all(username, targetName);

  return hasActiveTargetRoleAssignment(assignments);
}

function getAssignedApplicationRole(db, username) {
  if (!db || typeof username !== "string" || username.length === 0) {
    return "developer";
  }
  const permissions = db
    .prepare(`
      SELECT
        MAX(ar.targets_create) AS targets_create,
        MAX(ar.targets_edit) AS targets_edit,
        MAX(ar.targets_delete) AS targets_delete,
        MAX(ar.users_create) AS users_create,
        MAX(ar.users_edit) AS users_edit,
        MAX(ar.users_delete) AS users_delete,
        MAX(ar.access_roles_create) AS access_roles_create,
        MAX(ar.access_roles_edit) AS access_roles_edit,
        MAX(ar.access_roles_delete) AS access_roles_delete,
        MAX(ar.access_roles_assign) AS access_roles_assign,
        MAX(ar.sessions_view) AS sessions_view,
        MAX(ar.sessions_terminate) AS sessions_terminate,
        MAX(ar.recordings_view) AS recordings_view,
        MAX(ar.tickets_create) AS tickets_create,
        MAX(ar.tickets_delete) AS tickets_delete,
        MAX(ar.config_edit) AS config_edit,
        MAX(ar.admin_roles_manage) AS admin_roles_manage,
        MAX(ar.ticket_requests_manage) AS ticket_requests_manage
      FROM users u
      JOIN user_admin_roles uar ON uar.user_id = u.id
      JOIN admin_roles ar ON ar.id = uar.admin_role_id
      WHERE lower(u.username) = lower(?)
    `)
    .get(username);
  if (
    permissions &&
    Object.values(permissions).every((permission) => permission === 1)
  ) {
    return "admin";
  }

  const roleTable = db
    .prepare(`
      SELECT 1
      FROM sqlite_master
      WHERE type = 'table' AND name = 'secure_access_user_roles'
    `)
    .get();
  if (!roleTable) {
    return "developer";
  }
  const row = db
    .prepare(`
      SELECT sar.application_role
      FROM secure_access_user_roles sar
      JOIN users u ON u.id = sar.user_id
      WHERE lower(u.username) = lower(?)
    `)
    .get(username);
  return row?.application_role === "auditor_viewer"
    ? "auditor_viewer"
    : "developer";
}

function getUserAccessibleTargets(db, username) {
  if (!db || typeof username !== "string" || username.length === 0) {
    return [];
  }
  const assignments = db
    .prepare(`
      SELECT t.id AS target_id, t.name AS target_name,
             ur.granted_at, ur.expires_at, ur.revoked_at
      FROM users u
      JOIN user_roles ur ON ur.user_id = u.id
      JOIN roles r ON r.id = ur.role_id
      JOIN target_roles tr ON tr.role_id = r.id
      JOIN targets t ON t.id = tr.target_id
      WHERE lower(u.username) = lower(?)
    `)
    .all(username);
  const grouped = new Map();
  for (const assignment of assignments) {
    const key = assignment.target_id;
    const target = grouped.get(key) || {
      id: assignment.target_id,
      name: assignment.target_name,
      assignments: [],
    };
    target.assignments.push(assignment);
    grouped.set(key, target);
  }
  return [...grouped.values()]
    .filter((target) => hasActiveTargetRoleAssignment(target.assignments))
    .map((target) => ({ id: target.id, name: target.name }));
}

function parseSessionTargetSnapshot(targetSnapshot) {
  if (typeof targetSnapshot !== "string" || !targetSnapshot) {
    return null;
  }

  try {
    const target = JSON.parse(targetSnapshot);
    return target && typeof target === "object" && !Array.isArray(target)
      ? target
      : null;
  } catch {
    return null;
  }
}

function isWarpgateSessionVisible(
  session,
  applicationRole,
  username,
  accessibleTargets,
) {
  if (!session) {
    return false;
  }
  if (applicationRole === "admin") {
    return true;
  }
  if (
    !["developer", "auditor_viewer"].includes(applicationRole) ||
    typeof username !== "string" ||
    !username.trim() ||
    typeof session?.username !== "string" ||
    !session.username.trim() ||
    session.username.trim().toLowerCase() === "unknown"
  ) {
    return false;
  }

  const target = parseSessionTargetSnapshot(session.target_snapshot);
  if (typeof target?.id !== "string" || !target.id.trim()) {
    return false;
  }

  if (applicationRole === "auditor_viewer") {
    return true;
  }

  return Array.isArray(accessibleTargets) &&
    accessibleTargets.some(
      (accessibleTarget) =>
        typeof accessibleTarget?.id === "string" &&
        accessibleTarget.id.toLowerCase() === target.id.toLowerCase(),
    ) &&
    session.username.trim().toLowerCase() === username.trim().toLowerCase();
}

function listVisibleWarpgateSessions(
  database,
  applicationRole,
  username,
  accessibleTargets,
) {
  const pageSize = 500;
  const statement = database.prepare(`
    SELECT id, target_snapshot, username, started, ended, ticket_id,
           protocol, node_id
    FROM sessions
    ORDER BY started DESC
    LIMIT @limit OFFSET @offset
  `);
  const visibleSessions = [];
  let offset = 0;

  while (visibleSessions.length < pageSize) {
    const rows = statement.all({ limit: pageSize, offset });
    for (const session of rows) {
      if (applicationRole !== "admin") {
        const target = parseSessionTargetSnapshot(session.target_snapshot);
        if (session.target_snapshot && !target) {
          console.warn(
            "Skipping Warpgate session with malformed target metadata:",
            session.id,
          );
        }
        if (
          !isWarpgateSessionVisible(
            session,
            applicationRole,
            username,
            accessibleTargets,
          )
        ) {
          continue;
        }
      }

      const target = parseSessionTargetSnapshot(session.target_snapshot);
      const { target_snapshot: _, ...sessionData } = session;
      visibleSessions.push({
        ...sessionData,
        target: typeof target?.name === "string" ? target.name : null,
      });
      if (visibleSessions.length === pageSize) {
        break;
      }
    }

    if (rows.length < pageSize || applicationRole === "admin") {
      break;
    }
    offset += pageSize;
  }

  return visibleSessions;
}

module.exports = {
  getAssignedApplicationRole,
  getUserAccessibleTargets,
  hasTargetRoleAssignment,
  isWarpgateSessionVisible,
  listVisibleWarpgateSessions,
  parseSessionTargetSnapshot,
};
