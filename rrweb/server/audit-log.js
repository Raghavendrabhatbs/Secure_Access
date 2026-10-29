const crypto = require("node:crypto");

const EVENT_NAME_PATTERN = /^[a-z][a-z0-9_.-]{0,79}$/;
const SENSITIVE_KEY_PATTERN = /password|secret|token|credential|private.?key/i;

function initializeAuditStore(database) {
  database.exec(`
    CREATE TABLE IF NOT EXISTS secure_access_audit_events (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      username TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      session_id TEXT,
      details_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS secure_access_audit_timestamp_idx
      ON secure_access_audit_events(timestamp DESC);
  `);
}

function normalizeAuditEvent(event, username, now = new Date()) {
  if (
    !event ||
    typeof event !== "object" ||
    Array.isArray(event) ||
    typeof username !== "string" ||
    !username.trim() ||
    !EVENT_NAME_PATTERN.test(event.category || "") ||
    !EVENT_NAME_PATTERN.test(event.action || "")
  ) {
    return null;
  }

  const details = {};
  if (event.details !== undefined) {
    if (
      !event.details ||
      typeof event.details !== "object" ||
      Array.isArray(event.details)
    ) {
      return null;
    }

    for (const [key, value] of Object.entries(event.details)) {
      if (key.length > 64) {
        return null;
      }
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        continue;
      }
      if (
        !(
          value === null ||
          typeof value === "boolean" ||
          (typeof value === "number" && Number.isFinite(value)) ||
          (typeof value === "string" && value.length <= 256)
        )
      ) {
        return null;
      }
      details[key] = value;
    }
  }

  if (JSON.stringify(details).length > 2048) {
    return null;
  }

  const target =
    typeof details.target === "string" ? details.target : null;
  const sessionId =
    typeof details.sessionId === "string" ? details.sessionId : null;

  return {
    id: crypto.randomUUID(),
    timestamp: now.toISOString(),
    username: username.trim().slice(0, 128),
    category: event.category,
    action: event.action,
    target: target?.slice(0, 256) || null,
    sessionId: sessionId?.slice(0, 128) || null,
    detailsJson: JSON.stringify(details),
  };
}

function insertAuditEvent(database, event) {
  database
    .prepare(`
      INSERT INTO secure_access_audit_events
        (id, timestamp, username, category, action, target, session_id, details_json)
      VALUES
        (@id, @timestamp, @username, @category, @action, @target, @sessionId, @detailsJson)
    `)
    .run(event);
}

function listAuditEvents(
  database,
  { limit = 100, search = "", username, targetNames } = {},
) {
  const numericLimit = Number(limit);
  const boundedLimit = Number.isFinite(numericLimit)
    ? Math.min(Math.max(numericLimit, 1), 500)
    : 100;
  const normalizedSearch =
    typeof search === "string" ? search.trim().slice(0, 200) : "";
  const bindings = { limit: boundedLimit };
  const conditions = [];
  if (normalizedSearch) {
    conditions.push(`(
      username LIKE @search OR category LIKE @search OR action LIKE @search
      OR target LIKE @search OR details_json LIKE @search
    )`);
    bindings.search = `%${normalizedSearch}%`;
  }

  if (typeof username === "string") {
    const scopedTargets = Array.isArray(targetNames) ? targetNames : [];
    const targetBindings = scopedTargets.map((target, index) => {
      const key = `target${index}`;
      bindings[key] = target;
      return `@${key}`;
    });
    const targetCondition = targetBindings.length
      ? ` OR target IN (${targetBindings.join(", ")})`
      : "";
    conditions.push(`(username = @username${targetCondition})`);
    bindings.username = username;
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const rows = database
    .prepare(`
      SELECT id, timestamp, username, category, action, target, session_id, details_json
      FROM secure_access_audit_events
      ${where}
      ORDER BY timestamp DESC
      LIMIT @limit
    `)
    .all(bindings);

  return rows.map(({ details_json: detailsJson, ...row }) => ({
    ...row,
    details: JSON.parse(detailsJson),
  }));
}

module.exports = {
  initializeAuditStore,
  insertAuditEvent,
  listAuditEvents,
  normalizeAuditEvent,
};
