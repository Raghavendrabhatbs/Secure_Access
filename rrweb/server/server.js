const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const os = require("os");
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const getSigningSecret =
  require("../shared/signing-secret");
const RRWEB_SIGNING_SECRET =
  getSigningSecret();
console.info("RRweb recording-token verification is configured");

let warpgateApiOrigin;
try {
  warpgateApiOrigin = new URL(
    process.env.WARPGATE_API_URL || "https://localhost:8888",
  );
} catch {
  throw new Error("WARPGATE_API_URL must be an absolute HTTP(S) origin");
}
if (
  !["http:", "https:"].includes(warpgateApiOrigin.protocol) ||
  warpgateApiOrigin.username ||
  warpgateApiOrigin.password ||
  warpgateApiOrigin.pathname !== "/" ||
  warpgateApiOrigin.search ||
  warpgateApiOrigin.hash
) {
  throw new Error("WARPGATE_API_URL must be an absolute HTTP(S) origin");
}
const warpgateHostname = warpgateApiOrigin.hostname.replace(/^\[|\]$/g, "");
const warpgateIsLoopback = ["localhost", "127.0.0.1", "::1"].includes(
  warpgateHostname,
);
const allowInsecureWarpgateTls =
  process.env.WARPGATE_INSECURE_TLS === "true";
if (warpgateApiOrigin.protocol === "http:" && !warpgateIsLoopback) {
  throw new Error("WARPGATE_API_URL may use HTTP only for a loopback host");
}
if (allowInsecureWarpgateTls && !warpgateIsLoopback) {
  throw new Error("WARPGATE_INSECURE_TLS is permitted only for loopback");
}
if (allowInsecureWarpgateTls) {
  console.warn(
    "WARPGATE_INSECURE_TLS is enabled for the loopback development connection",
  );
}
const warpgateHttpsAgent =
  warpgateApiOrigin.protocol === "https:"
    ? new https.Agent({
        rejectUnauthorized: !allowInsecureWarpgateTls,
        ca: process.env.WARPGATE_TLS_CA_FILE
          ? fs.readFileSync(process.env.WARPGATE_TLS_CA_FILE)
          : undefined,
      })
    : undefined;
const {
  appendIdempotentBatch,
  appendRecordingFailure,
  authorizeRecordingToken,
  canControlRecordingByPolicy,
  canWriteRecordingByApplicationRole,
  canViewRecordingByPolicy,
  canWatchActiveWebRecording,
  getRecordingLifecycleStatus,
  isRecordingFinalized,
  isValidEventBatch,
  isValidRecordingFailure,
  isValidSessionId,
  isValidVisitId,
  redactPageUrl,
  recordingIdentityMatchesMetadata,
} = require("./recording-utils");
const {
  getAssignedApplicationRole,
  getUserAccessibleTargets,
  hasTargetRoleAssignment,
  listVisibleWarpgateSessions,
} = require("./warpgate-rbac");
const {
  initializeAuditStore,
  insertAuditEvent,
  listAuditEvents,
  normalizeAuditEvent,
} = require("./audit-log");

function authenticateRecordingRequest(req, res, next) {
  const authorization = authorizeRecordingToken(
    req.headers.authorization,
    RRWEB_SIGNING_SECRET,
    canControlRecordingByPolicy,
  );
  if (!authorization.identity) {
    if (authorization.statusCode === 403) {
      console.warn("RRWeb recording request denied:", authorization.error);
    }
    return res
      .status(authorization.statusCode)
      .json({ error: authorization.error });
  }

  const applicationRole = getAssignedApplicationRole(
    warpgateDb,
    authorization.identity.username,
  );
  if (!canWriteRecordingByApplicationRole(applicationRole)) {
    return res.status(403).json({ error: "Auditor/Viewer access is read-only" });
  }

  req.recordingIdentity = authorization.identity;
  next();
}


const app = express();         

const PORT = 3000;
const allowedCorsOrigins = new Set(
  (
    process.env.RRWEB_ALLOWED_ORIGINS ||
    "http://localhost:5173"
  )
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);


// ==================================================
// PATHS
// ==================================================

const recordingsDir =
  path.join(
    __dirname,
    "recordings"
  );

const metadataDir =
  path.join(
    __dirname,
    "metadata"
  );


const configuredWarpgateDatabasePath =
  process.env.WARPGATE_DATABASE_PATH;

const defaultLinuxWarpgateDatabasePath =
  path.join(
    path.parse(process.cwd()).root,
    "var",
    "lib",
    "warpgate",
    "db",
    "db.sqlite3"
  );

const homeWarpgateDatabasePath =
  path.join(
    os.homedir(),
    "warpgate",
    "data",
    "db",
    "db.sqlite3"
  );

const legacyWarpgateDatabasePath =
  path.join(
    os.homedir(),
    "warpgate-local",
    "data",
    "db",
    "db.sqlite3"
  );

const defaultWarpgateDatabasePaths = [
  defaultLinuxWarpgateDatabasePath,
  homeWarpgateDatabasePath,
  legacyWarpgateDatabasePath,
].filter((candidate) => fs.existsSync(candidate));

if (!configuredWarpgateDatabasePath && defaultWarpgateDatabasePaths.length > 1) {
  throw new Error(
    "Multiple Warpgate databases were found. Set WARPGATE_DATABASE_PATH to the database used by the active Warpgate server.",
  );
}

const warpgateDatabasePath =
  configuredWarpgateDatabasePath
    ? path.resolve(configuredWarpgateDatabasePath)
    : defaultWarpgateDatabasePaths[0] || legacyWarpgateDatabasePath;


// ==================================================
// EXPRESS
// ==================================================
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedCorsOrigins.has(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin is not allowed by rrweb CORS policy"));
    },
    credentials: true,
  })
);
app.use(
  express.json({
    limit: "50mb",
  })
);

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);


// ==================================================
// CREATE STORAGE DIRECTORIES
// ==================================================

if (
  !fs.existsSync(
    recordingsDir
  )
) {

  fs.mkdirSync(
    recordingsDir,
    {
      recursive: true,
    }
  );

}


if (
  !fs.existsSync(
    metadataDir
  )
) {

  fs.mkdirSync(
    metadataDir,
    {
      recursive: true,
    }
  );

}


// ==================================================
// WARPGATE DATABASE
// ==================================================

if (
  !fs.existsSync(
    warpgateDatabasePath
  )
) {

  console.error(
    "Warpgate database not found:"
  );

  console.error(
    warpgateDatabasePath
  );

  process.exit(1);

}


const warpgateDb =
  new Database(
    warpgateDatabasePath,
    {
      readonly: true,
      fileMustExist: true,
    }
  );

const auditDatabasePath = process.env.SECURE_ACCESS_AUDIT_DB_PATH
  ? path.resolve(process.env.SECURE_ACCESS_AUDIT_DB_PATH)
  : path.join(metadataDir, "secure-access-audit.sqlite3");
fs.mkdirSync(path.dirname(auditDatabasePath), { recursive: true });
const auditDb = new Database(auditDatabasePath);
initializeAuditStore(auditDb);


console.log(
  "Connected to Warpgate database:"
);

console.log(
  warpgateDatabasePath
);


// ==================================================
// ACTIVE RRWEB SESSIONS
// ==================================================

const sessions =
  new Map();


const sessionMetadata =
  new Map();

function findWarpgateSessionForRecording(metadata) {
  if (
    typeof metadata?.warpgateSessionId !== "string" ||
    !/^[0-9a-f-]{36}$/i.test(metadata.warpgateSessionId)
  ) {
    return null;
  }

  return warpgateDb
    .prepare(`
      SELECT id, username, started, ended, protocol, target_snapshot
      FROM sessions
      WHERE id = ?
    `)
    .get(metadata.warpgateSessionId) || null;
}

function canWatchWebSession(identity, sessionId, metadata, warpgateSession) {
  return canWatchActiveWebRecording(
    identity?.applicationRole,
    sessionId,
    metadata,
    warpgateSession,
    getWarpgateUserId(warpgateSession?.username),
    sessions.has(sessionId),
  );
}

function writeWatchEvent(res, event, data, id) {
  const eventId = Number.isSafeInteger(id) ? `id: ${id}\n` : "";
  const payload = `${eventId}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  if (res.destroyed) {
    return Promise.resolve(false);
  }
  if (res.write(payload)) {
    return Promise.resolve(true);
  }

  return new Promise((resolve) => {
    const cleanup = () => {
      res.off("drain", onDrain);
      res.off("close", onClose);
    };
    const onDrain = () => {
      cleanup();
      resolve(!res.destroyed);
    };
    const onClose = () => {
      cleanup();
      resolve(false);
    };
    res.once("drain", onDrain);
    res.once("close", onClose);
  });
}


// ==================================================
// FILE HELPERS
// ==================================================

function getRecordingPath(
  sessionId
) {

  return path.join(
    recordingsDir,
    `${sessionId}.json`
  );

}


function getMetadataPath(
  sessionId
) {

  return path.join(
    metadataDir,
    `${sessionId}.json`
  );

}


function saveSession(
  sessionId
) {

  const events =
    sessions.get(
      sessionId
    );


  if (!events) {
    return;
  }


  atomicWriteJson(getRecordingPath(sessionId), events);

}


function saveMetadata(
  sessionId
) {

  const metadata =
    sessionMetadata.get(
      sessionId
    );


  if (!metadata) {
    return;
  }


  atomicWriteJson(getMetadataPath(sessionId), metadata);

}

function atomicWriteJson(filepath, value) {
  const temporaryPath = path.join(
    path.dirname(filepath),
    `.${path.basename(filepath)}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  try {
    fs.writeFileSync(temporaryPath, JSON.stringify(value, null, 2), {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    fs.renameSync(temporaryPath, filepath);
  } catch (error) {
    try {
      if (fs.existsSync(temporaryPath)) {
        fs.unlinkSync(temporaryPath);
      }
    } catch (cleanupError) {
      console.error(`Unable to remove temporary file ${temporaryPath}:`, cleanupError);
    }
    throw error;
  }
}


function loadMetadata(
  sessionId
) {

  const filepath =
    getMetadataPath(
      sessionId
    );


  if (
    !fs.existsSync(
      filepath
    )
  ) {

    return null;

  }


  try {

    return JSON.parse(

      fs.readFileSync(
        filepath,
        "utf8"
      )

    );

  } catch (error) {

    console.error(
      `Unable to read metadata for ${sessionId}:`,
      error.message
    );

    return null;

  }

}


// ==================================================
// SESSION ID / FILENAME VALIDATION
// ==================================================

function loadSessionEvents(sessionId) {
  const filepath = getRecordingPath(sessionId);
  if (!fs.existsSync(filepath)) {
    return [];
  }

  const events = JSON.parse(fs.readFileSync(filepath, "utf8"));
  if (!Array.isArray(events)) {
    throw new Error(`Recording ${sessionId} does not contain an event array`);
  }
  return events;
}


function sessionIdFromFilename(
  filename
) {

  if (
    typeof filename !== "string"
  ) {

    return null;

  }


  if (
    !/^session-[A-Za-z0-9_-]+\.json$/.test(
      filename
    )
  ) {

    return null;

  }


  return filename.replace(
    /\.json$/,
    ""
  );

}


// ==================================================
// WARPGATE RBAC HELPERS
// ==================================================

// --------------------------------------------------
// GET USER ROLES FROM WARPGATE
// --------------------------------------------------

function getWarpgateUserId(username) {
  if (!username) {
    return null;
  }

  const row = warpgateDb
    .prepare(`
      SELECT id
      FROM users
      WHERE lower(username) = lower(?)
      LIMIT 1
    `)
    .get(username);
  return typeof row?.id === "string" ? row.id : null;
}

// --------------------------------------------------
// DOES USER STILL HAVE ACCESS TO TARGET?
// --------------------------------------------------

function hasTargetAccess(
  username,
  targetName,
  applicationRole,
) {
  if (
    !username ||
    !targetName
  ) {
    return false;
  }

  if (applicationRole === "admin") {
    return true;
  }

  return hasTargetRoleAssignment(warpgateDb, username, targetName);
}

function getUserAccessibleTargetNames(username) {
  return getUserAccessibleTargets(warpgateDb, username).map(
    (target) => target.name,
  );
}

function canViewRecording(
  requesterUsername,
  metadata,
  applicationRole,
) {
  const authorizedTargetNames = applicationRole === "developer"
    ? getUserAccessibleTargetNames(requesterUsername)
    : [];
  return canViewRecordingByPolicy(
    requesterUsername,
    applicationRole,
    metadata,
    authorizedTargetNames,
  );
}

// ==================================================
// RECORDING CONTROL RBAC
// ==================================================

// ==================================================
// WARPGATE SESSION AUTHENTICATION
// ==================================================

function getWarpgateIdentity(req) {
  return new Promise((resolve) => {
    const cookie = req.headers.cookie;

    if (!cookie) {
      resolve(null);
      return;
    }

    const requestUrl = new URL(
      "/@warpgate/api/info",
      warpgateApiOrigin,
    );
    const transport =
      requestUrl.protocol === "https:" ? https : http;
    const request = transport.request(
      requestUrl,
      {
        method: "GET",
        headers: {
          Cookie: cookie,
        },
        agent: warpgateHttpsAgent,
        timeout: 5000,
      },

      (response) => {
        let body = "";
        let receivedBytes = 0;
        let bodyTooLarge = false;

        response.on(
          "data",
          (chunk) => {
            if (receivedBytes + chunk.length > 64 * 1024) {
              bodyTooLarge = true;
              request.destroy(new Error("Warpgate identity response exceeded its limit"));
              return;
            }
            receivedBytes += chunk.length;
            body += chunk;
          }
        );

        response.on(
          "end",
          () => {
            if (bodyTooLarge) {
              resolve(null);
              return;
            }
            if (response.statusCode !== 200) {
              console.warn(
                "Warpgate identity check returned an unexpected status:",
                response.statusCode,
              );
              resolve(null);
              return;
            }

            try {
              const info = JSON.parse(body);

              if (
                !info.username ||
                typeof info.username !== "string"
              ) {
                resolve(null);
                return;
              }

              resolve({
                username: info.username,
                adminPermissions:
                  info.admin_permissions || {},
                applicationRole:
                  ["admin", "developer", "auditor_viewer"].includes(
                    info.application_role,
                  )
                    ? info.application_role
                    : getAssignedApplicationRole(warpgateDb, info.username),
              });

            } catch (error) {
              console.error(
                "Unable to parse Warpgate identity:",
                error.message
              );

              resolve(null);
            }
          }
        );
      }
    );

    request.on(
      "error",
      (error) => {
        console.error(
          "Unable to verify Warpgate session:",
          error.message
        );

        resolve(null);
      }
    );

    request.on("timeout", () => {
      request.destroy(new Error("Warpgate identity request timed out"));
    });

    request.end();
  });
}


async function authenticateWarpgateRequest(
  req,
  res,
  next
) {
  const identity =
    await getWarpgateIdentity(req);

  if (!identity) {
    return res
      .status(401)
      .json({
        error: "Authentication required",
      });
  }

  req.warpgateIdentity = identity;

  next();
}


function getRequestUsername(req) {
  return (
    req.warpgateIdentity?.username ||
    null
  );
}

app.post(
  "/api/audit/events",
  authenticateWarpgateRequest,
  (req, res) => {
    const event = normalizeAuditEvent(
      req.body,
      getRequestUsername(req),
    );
    if (!event) {
      return res.status(400).json({ error: "Invalid audit event" });
    }

    insertAuditEvent(auditDb, event);
    return res.status(201).json({ success: true, id: event.id });
  },
);

app.get(
  "/api/audit/events",
  authenticateWarpgateRequest,
  (req, res) => {
    const { applicationRole } = req.warpgateIdentity;
    if (!["admin", "auditor_viewer"].includes(applicationRole)) {
      return res.status(403).json({ error: "Audit-log access is not permitted" });
    }

    return res.json(
      listAuditEvents(auditDb, {
        limit: req.query.limit,
        search: req.query.search,
      }),
    );
  },
);

app.get(
  "/api/audit/warpgate-events",
  authenticateWarpgateRequest,
  (req, res) => {
    const { applicationRole } = req.warpgateIdentity;
    if (!["admin", "auditor_viewer"].includes(applicationRole)) {
      return res.status(403).json({ error: "Audit-log access is not permitted" });
    }

    const requestedLimit = Number(req.query.limit);
    const limit = Number.isFinite(requestedLimit)
      ? Math.min(Math.max(Math.floor(requestedLimit), 1), 500)
      : 100;
    const bindings = { limit };
    const filters = [];
    if (typeof req.query.search === "string" && req.query.search.trim()) {
      filters.push("(text LIKE @search OR username LIKE @search OR target LIKE @search OR \"values\" LIKE @search)");
      bindings.search = `%${req.query.search.trim().slice(0, 200)}%`;
    }
    if (typeof req.query.username === "string" && req.query.username) {
      filters.push("username = @filterUsername");
      bindings.filterUsername = req.query.username.slice(0, 128);
    }
    if (typeof req.query.target === "string" && req.query.target) {
      filters.push("target = @filterTarget");
      bindings.filterTarget = req.query.target.slice(0, 256);
    }

    const rows = warpgateDb
      .prepare(`
        SELECT id, text, target, "values" AS values_json, timestamp,
               session_id, username, related_users, related_access_roles,
               related_admin_roles
        FROM log
        ${filters.length ? `WHERE ${filters.join(" AND ")}` : ""}
        ORDER BY timestamp DESC
        LIMIT @limit
      `)
      .all(bindings)
      .map(({ values_json: valuesJson, ...row }) => ({
        ...row,
        values: typeof valuesJson === "string" ? JSON.parse(valuesJson) : valuesJson,
      }));
    return res.json(rows);
  },
);

app.get(
  "/api/warpgate/sessions",
  authenticateWarpgateRequest,
  (req, res) => {
    const { applicationRole, username } = req.warpgateIdentity;
    if (!["admin", "developer", "auditor_viewer"].includes(applicationRole)) {
      return res.status(403).json({ error: "Session access is not permitted" });
    }

    const accessibleTargets = applicationRole === "admin"
      ? []
      : getUserAccessibleTargets(warpgateDb, username);
    if (applicationRole === "developer" && accessibleTargets.length === 0) {
      return res.json([]);
    }
    return res.json(
      listVisibleWarpgateSessions(
        warpgateDb,
        applicationRole,
        username,
        accessibleTargets,
      ),
    );
  },
);

app.get(
  "/api/sessions/:sessionId/watch",
  authenticateWarpgateRequest,
  async (req, res) => {
    const identity = req.warpgateIdentity;
    const { sessionId } = req.params;
    if (identity.applicationRole !== "admin") {
      return res.status(403).json({ error: "Live session Watch is Admin-only" });
    }
    if (!isValidSessionId(sessionId)) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    let metadata = sessionMetadata.get(sessionId) || loadMetadata(sessionId);
    if (!metadata) {
      return res.status(404).json({ error: "Session recording not found" });
    }
    let warpgateSession;
    try {
      warpgateSession = findWarpgateSessionForRecording(metadata);
    } catch (error) {
      console.error("Unable to verify the Warpgate session for Watch:", error.message);
      return res.status(503).json({ error: "Unable to verify the active session" });
    }
    if (!canWatchWebSession(identity, sessionId, metadata, warpgateSession)) {
      return res.status(409).json({
        error: "This web recording is not attached to a verified active session",
      });
    }

    res.status(200);
    res.set({
      "Cache-Control": "no-cache, no-transform",
      "Content-Type": "text/event-stream; charset=utf-8",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.flushHeaders();
    res.write(": connected\n\n");

    let closed = false;
    const activeEvents = sessions.get(sessionId);
    const lastEventId = req.get("Last-Event-ID");
    const requestedSequence =
      typeof lastEventId === "string" && /^(0|[1-9]\d*)$/.test(lastEventId)
        ? Number(lastEventId)
        : -1;
    let cursor =
      Number.isSafeInteger(requestedSequence) &&
      requestedSequence < activeEvents.length
        ? requestedSequence + 1
        : 0;
    let lastAuthorizationCheck = Date.now();
    let pollTimer;
    const requester = identity.username.toLowerCase();
    const closeStream = () => {
      if (closed) {
        return;
      }
      closed = true;
      clearTimeout(pollTimer);
      if (!res.destroyed) {
        res.end();
      }
    };
    res.on("close", () => {
      closed = true;
      clearTimeout(pollTimer);
    });

    if (!(await writeWatchEvent(res, "session", {
      sessionId,
      warpgateSessionId: metadata.warpgateSessionId,
      username: metadata.username,
      target: metadata.target,
      startedAt: metadata.startedAt,
      protocol: warpgateSession.protocol,
    }))) {
      closeStream();
      return;
    }

    const poll = async () => {
      if (closed) {
        return;
      }
      try {
        if (Date.now() - lastAuthorizationCheck >= 10_000) {
          const currentIdentity = await getWarpgateIdentity(req);
          if (
            currentIdentity?.applicationRole !== "admin" ||
            currentIdentity.username.toLowerCase() !== requester
          ) {
            await writeWatchEvent(res, "state", { state: "authorization-revoked" });
            closeStream();
            return;
          }
          lastAuthorizationCheck = Date.now();
        }

        metadata = sessionMetadata.get(sessionId) || loadMetadata(sessionId);
        if (!metadata) {
          await writeWatchEvent(res, "state", { state: "recording-unavailable" });
          closeStream();
          return;
        }
        warpgateSession = findWarpgateSessionForRecording(metadata);
        if (!warpgateSession) {
          await writeWatchEvent(res, "state", { state: "session-unavailable" });
          closeStream();
          return;
        }

        const finalized = isRecordingFinalized(
          metadata,
          sessions.has(sessionId),
          fs.existsSync(getRecordingPath(sessionId)),
        );
        const liveEvents = sessions.get(sessionId);
        const events = liveEvents || (finalized ? loadSessionEvents(sessionId) : null);
        if (!events) {
          const state = warpgateSession.ended !== null
            ? "finalization-pending"
            : "recording-unavailable";
          await writeWatchEvent(res, "state", { state });
          closeStream();
          return;
        }

        if (
          !finalized &&
          !canWatchWebSession(identity, sessionId, metadata, warpgateSession)
        ) {
          const state = warpgateSession.ended !== null
            ? "finalization-pending"
            : "recording-unavailable";
          await writeWatchEvent(res, "state", { state });
          closeStream();
          return;
        }

        const end = Math.min(events.length, cursor + 100);
        while (cursor < end) {
          if (!(await writeWatchEvent(res, "rrweb", {
            sequence: cursor,
            event: events[cursor],
          }, cursor))) {
            closeStream();
            return;
          }
          cursor += 1;
        }

        if (finalized && cursor >= events.length) {
          await writeWatchEvent(res, "state", { state: "completed" });
          closeStream();
          return;
        }
        if (cursor < events.length) {
          pollTimer = setTimeout(poll, 0);
        } else {
          res.write(": keepalive\n\n");
          pollTimer = setTimeout(poll, 500);
        }
      } catch (error) {
        console.error("Live web Watch stream failed:", error.message);
        await writeWatchEvent(res, "state", { state: "stream-error" });
        closeStream();
      }
    };

    await poll();
  },
);

// ==================================================
// START / RESUME RECORDING SESSION
// ==================================================
app.post(
  "/api/sessions/start",
  authenticateRecordingRequest,

  (req, res) => {
    const {
      sessionId,
      visitId,
      username: requestUsername,
      target: requestTarget,
      authenticationType: requestAuthenticationType,
      pageUrl,
      pageTitle,
      referrer,
      navigationType,
    } = req.body;
    const identity = req.recordingIdentity;
    const { username, target, authenticationType, recordingSessionId } = identity;

    if (!isValidSessionId(sessionId) || sessionId !== recordingSessionId) {
      return res.status(400).json({ error: "Invalid or unbound sessionId" });
    }
    if (
      !isValidVisitId(visitId) ||
      requestUsername !== username ||
      requestTarget !== target ||
      requestAuthenticationType !== authenticationType
    ) {
      return res.status(400).json({ error: "Page visit does not match its token" });
    }
    if (
      !canControlRecordingByPolicy(
        username,
        target,
        authenticationType,
      )
    ) {
      console.log(`RBAC DENIED start recording: ${username} -> ${target}`);
      return res
        .status(403)
        .json({ error: "You are not allowed to start recordings" });
    }

    const now = new Date().toISOString();
    let metadata = sessionMetadata.get(sessionId) || loadMetadata(sessionId);
    if (fs.existsSync(getMetadataPath(sessionId)) && !metadata) {
      return res.status(500).json({ error: "Existing session metadata is unreadable" });
    }
    if (metadata) {
      metadata = structuredClone(metadata);
    }
    if (metadata?.stoppedAt || metadata?.recordingStatus === "stopped") {
      return res.status(409).json({ error: "This recording has already stopped" });
    }
    if (
      metadata &&
      (metadata.username !== username ||
        metadata.authenticationType !== authenticationType ||
        metadata.target !== target ||
      (metadata.warpgateUserId != null &&
        metadata.warpgateUserId !== identity.warpgateUserId) ||
      (metadata.warpgateSessionId != null &&
          metadata.warpgateSessionId !== identity.warpgateSessionId))
    ) {
      return res.status(403).json({ error: "Session identity mismatch" });
    }

    let events = sessions.get(sessionId);
    if (!events) {
      events = loadSessionEvents(sessionId);
      sessions.set(sessionId, events);
    }

    metadata ||= {
      sessionId,
      username,
      authenticationType,
      target,
      warpgateUserId: identity.warpgateUserId || null,
      warpgateSessionId: identity.warpgateSessionId || null,
      startedAt: now,
      targets: [],
      pageVisits: [],
      batchIds: [],
      eventCount: events.length,
    };
    metadata.warpgateSessionId =
      metadata.warpgateSessionId || identity.warpgateSessionId || null;
    metadata.warpgateUserId =
      metadata.warpgateUserId || identity.warpgateUserId || null;
    metadata.recordingStatus = "starting";
    metadata.targets = Array.isArray(metadata.targets)
      ? metadata.targets
      : [metadata.target].filter(Boolean);
    metadata.pageVisits = Array.isArray(metadata.pageVisits)
      ? metadata.pageVisits
      : [];
    metadata.batchIds = Array.isArray(metadata.batchIds)
      ? metadata.batchIds
      : [];
    if (!metadata.targets.includes(target)) {
      metadata.targets.push(target);
    }

    const safePageUrl = redactPageUrl(pageUrl);
    const existingVisit = metadata.pageVisits.some(
      (visit) => visit.visitId === visitId,
    );
    if (!existingVisit) {
      metadata.pageVisits.push({
        visitId,
        pageUrl: safePageUrl,
        pageTitle: typeof pageTitle === "string" ? pageTitle.slice(0, 500) : null,
        referrer: redactPageUrl(referrer),
        target,
        navigationType:
          typeof navigationType === "string"
            ? navigationType.slice(0, 64)
            : "unknown",
        visitedAt: now,
      });
    }
    metadata.lastSeenAt = now;
    metadata.lastVisitedAt = now;
    metadata.lastPageUrl = safePageUrl || metadata.lastPageUrl || null;
    metadata.firstPageUrl = metadata.firstPageUrl || safePageUrl || null;
    delete metadata.stoppedAt;

    atomicWriteJson(getMetadataPath(sessionId), metadata);
    sessionMetadata.set(sessionId, metadata);
    console.log(`Registered page visit: ${sessionId} | ${target}`);
    return res.json({ success: true, sessionId, username });
  }
);


// ==================================================
// RECEIVE RRWEB EVENTS
// ==================================================
app.post(
  "/api/sessions/:sessionId/events",
  authenticateRecordingRequest,

  (req, res) => {
    const {
      sessionId
    } = req.params;

    if (
      !isValidSessionId(
        sessionId
      ) ||
      sessionId !== req.recordingIdentity.recordingSessionId
    ) {
      return res
        .status(400)
        .json({
          error:
            "Invalid session ID",
        });
    }

    if (!isValidEventBatch(req.body)) {
      return res.status(400).json({ error: "Invalid rrweb event batch" });
    }
    const { batchId, events } = req.body;

    if (
      !sessions.has(
        sessionId
      )
    ) {
      return res
        .status(404)
        .json({
          error:
            "Session not found",
        });
    }

    const metadata = sessionMetadata.get(sessionId);

    if (
      !recordingIdentityMatchesMetadata(
        req.recordingIdentity,
        metadata,
        sessionId,
      )
    ) {
      return res.status(403).json({
        error: "Session access denied"
      });
    }

    if (
      !Array.isArray(
        events
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "events must be an array",
        });
    }

    const sessionEvents =
      sessions.get(
        sessionId
      );

    const previousMetadata = structuredClone(metadata);
    const previousEventCount = sessionEvents.length;
    const previousBatchIds = Array.isArray(metadata.batchIds)
      ? metadata.batchIds.slice()
      : [];
    if (!appendIdempotentBatch(sessionEvents, metadata, batchId, events)) {
      return res.json({
        success: true,
        duplicate: true,
        totalEvents: sessionEvents.length,
      });
    }

    try {
      metadata.lastSeenAt =
        new Date()
          .toISOString();
      metadata.recordingStatus = "recording";
      if (metadata.lastFailure && !metadata.lastFailure.resolvedAt) {
        metadata.lastFailure.resolvedAt = metadata.lastSeenAt;
        metadata.lastFailure.resolution = "Recovered after a successful event upload";
      }

      sessionMetadata.set(sessionId, metadata);
      saveSession(sessionId);
      saveMetadata(
        sessionId
      );
    } catch (error) {
      sessionEvents.length = previousEventCount;
      previousMetadata.batchIds = previousBatchIds;
      previousMetadata.eventCount = previousEventCount;
      sessionMetadata.set(sessionId, previousMetadata);
      try {
        saveSession(sessionId);
      } catch (restoreError) {
        console.error(`Unable to restore recording ${sessionId} after a failed batch write:`, restoreError);
      }
      throw error;
    }

    console.log(
      `Session ${sessionId}: received ${events.length} events`
    );

    console.log(
      `Session ${sessionId}: total ${sessionEvents.length} events saved`
    );

    return res.json({
      success:
        true,

      totalEvents:
        sessionEvents.length,
    });
  }
);


// ==================================================
// STOP RECORDING SESSION
// ==================================================

app.post(
  "/api/sessions/:sessionId/stop",
  authenticateRecordingRequest,

  (req, res) => {

    const {
      sessionId
    } =
      req.params;


    if (
      !isValidSessionId(
        sessionId
      ) ||
      sessionId !== req.recordingIdentity.recordingSessionId
    ) {

      return res
        .status(400)
        .json({
          error:
            "Invalid session ID",
        });

    }


    if (
      !sessions.has(
        sessionId
      )
    ) {

      return res
        .status(404)
        .json({
          error:
            "Session not found",
        });

    }



const metadata = sessionMetadata.get(sessionId);

if (
  !recordingIdentityMatchesMetadata(
    req.recordingIdentity,
    metadata,
    sessionId,
  )
) {
  return res.status(403).json({ error: "Session access denied" });
}


    saveSession(
      sessionId
    );


    const eventCount =
      sessions
        .get(
          sessionId
        )
        .length;



    if (metadata) {

      metadata.stoppedAt =
        new Date()
          .toISOString();
      metadata.recordingStatus = "stopped";


      metadata.eventCount =
        eventCount;


      sessionMetadata.set(
        sessionId,
        metadata
      );


      saveMetadata(
        sessionId
      );

    }


    sessions.delete(
      sessionId
    );


    sessionMetadata.delete(
      sessionId
    );


    console.log(
      `Stopped session: ${sessionId} (${eventCount} events)`
    );


    return res.json({

      success:
        true,

      sessionId,

      events:
        eventCount,

    });

  }
);

app.post(
  "/api/sessions/:sessionId/heartbeat",
  authenticateRecordingRequest,
  (req, res) => {
    const { sessionId } = req.params;
    const identity = req.recordingIdentity;

    if (
      !isValidSessionId(sessionId) ||
      sessionId !== identity.recordingSessionId
    ) {
      return res.status(400).json({ error: "Invalid session ID" });
    }

    if (!sessions.has(sessionId)) {
      return res.status(404).json({ error: "Session not found" });
    }

    const metadata = sessionMetadata.get(sessionId);
    if (!recordingIdentityMatchesMetadata(identity, metadata, sessionId)) {
      return res.status(403).json({ error: "Session access denied" });
    }

    metadata.lastSeenAt = new Date().toISOString();
    if (metadata.recordingStatus !== "failed") {
      metadata.recordingStatus =
        Number(metadata.eventCount) > 0 ? "recording" : "starting";
    }
    saveMetadata(sessionId);

    return res.json({
      success: true,
      recordingStatus: metadata.recordingStatus,
    });
  },
);

app.post(
  "/api/sessions/:sessionId/failures",
  authenticateRecordingRequest,
  (req, res) => {
    const { sessionId } = req.params;
    const identity = req.recordingIdentity;
    const { stage, httpStatus } = req.body || {};

    if (
      !isValidSessionId(sessionId) ||
      sessionId !== identity.recordingSessionId
    ) {
      return res.status(400).json({ error: "Invalid session ID" });
    }
    if (!isValidRecordingFailure(stage, httpStatus)) {
      return res.status(400).json({ error: "Invalid recording failure details" });
    }

    let metadata = sessionMetadata.get(sessionId) || loadMetadata(sessionId);
    if (
      metadata &&
      !recordingIdentityMatchesMetadata(identity, metadata, sessionId)
    ) {
      return res.status(403).json({ error: "Session access denied" });
    }

    const now = new Date().toISOString();
    if (!metadata) {
      metadata = {
        sessionId,
        username: identity.username,
        authenticationType: identity.authenticationType,
        target: identity.target,
        warpgateUserId: identity.warpgateUserId || null,
        warpgateSessionId: identity.warpgateSessionId || null,
        targets: [identity.target],
        startedAt: now,
        eventCount: 0,
        pageVisits: [],
        batchIds: [],
      };
    }
    metadata.recordingStatus = "failed";
    metadata.lastSeenAt = now;
    const isDuplicate = appendRecordingFailure(
      metadata,
      stage,
      httpStatus,
      new Date(now),
    );

    sessionMetadata.set(sessionId, metadata);
    saveMetadata(sessionId);
    return res.status(202).json({ success: true, duplicate: isDuplicate });
  },
);

// ==================================================
// LIST RECORDINGS WITH RBAC + METADATA
// ==================================================

app.get(
  "/api/sessions",
   authenticateWarpgateRequest,


  (req, res) => {

    const requester =
      getRequestUsername(
        req
      );


    if (!requester) {

      return res
        .status(401)
        .json({
          error:
            "Authentication required",
        });

    }


    console.log(
      "Replay session list requested by:",
      requester
    );


    const files = fs
      .readdirSync(metadataDir)
      .filter((filename) =>
        /^session-[A-Za-z0-9_-]+\.json$/.test(filename),
      );


    const allowedSessions = [];


    for (
      const filename
      of files
    ) {

      const sessionId = sessionIdFromFilename(filename);


      if (!sessionId) {
        continue;
      }


      const metadata =
        loadMetadata(
          sessionId
        );


      if (!metadata) {
        continue;
      }


      // ----------------------------------------------
      // RBAC CHECK
      // ----------------------------------------------

      if (
        !canViewRecording(
          requester,
          metadata,
          req.warpgateIdentity.applicationRole,
        )
      ) {

        continue;

      }


      const recordingPath = getRecordingPath(sessionId);
      const hasRecording = fs.existsSync(recordingPath);
      let eventCount = Number(metadata.eventCount) || 0;
      let storageBytes = 0;
      try {
        storageBytes += fs.statSync(getMetadataPath(sessionId)).size;
        if (hasRecording) {
          storageBytes += fs.statSync(recordingPath).size;
        }
      } catch (error) {
        console.error(`Unable to measure recording storage for ${sessionId}:`, error.message);
      }


      /*
       * Older metadata files may not have
       * eventCount yet.
       *
       * Read the recording once so we can still
       * show the count in the player.
       */
      if (hasRecording && !eventCount) {

        try {

          const events =
            JSON.parse(
              fs.readFileSync(
                recordingPath,
                "utf8"
              )
            );


          if (
            Array.isArray(
              events
            )
          ) {

            eventCount =
              events.length;

          }

        } catch (error) {

          console.error(
            `Unable to count events for ${sessionId}:`,
            error.message
          );

        }

      }


      let warpgateSession = null;
      try {
        warpgateSession = findWarpgateSessionForRecording(metadata);
      } catch (error) {
        console.error(
          `Unable to verify Warpgate session for recording ${sessionId}:`,
          error.message,
        );
      }
      const recordingFinalized = isRecordingFinalized(
        metadata,
        sessions.has(sessionId),
        hasRecording,
      );
      const watchAvailable = canWatchWebSession(
        req.warpgateIdentity,
        sessionId,
        metadata,
        warpgateSession,
      );
      const recordingStatus = recordingFinalized
        ? "stopped"
        : watchAvailable
          ? "recording"
          : getRecordingLifecycleStatus(
        metadata,
        sessions.has(sessionId),
      );
      const lastFailure =
        metadata.lastFailure ||
        (recordingStatus === "failed"
          ? {
              timestamp: metadata.lastSeenAt || metadata.startedAt || null,
              stage: "lifecycle",
              httpStatus: null,
              message: sessions.has(sessionId)
                ? "No recording heartbeat was received within the allowed interval"
                : "Recording ended without a stop signal",
              resolvedAt: null,
            }
          : null);

      allowedSessions.push({

        file:
          filename,

        sessionId:
          sessionId,

        username:
          metadata.username
          ||
          "unknown",

        userId:
          getWarpgateUserId(metadata.username),

        target:
          metadata.target
          ||
          "unknown",

        startedAt:
          metadata.startedAt
          ||
          null,

        lastSeenAt:
          metadata.lastSeenAt
          ||
          null,

        firstPageUrl:
          metadata.firstPageUrl
          ||
          null,

        lastPageUrl:
          metadata.lastPageUrl
          ||
          null,

        eventCount,
        storageBytes,
        durationMs:
          metadata.startedAt && metadata.stoppedAt
            ? Math.max(
                0,
                new Date(metadata.stoppedAt).getTime() -
                  new Date(metadata.startedAt).getTime(),
              )
            : sessions.has(sessionId) && metadata.startedAt
              ? Math.max(
                  0,
                  Date.now() - new Date(metadata.startedAt).getTime(),
                )
              : null,
        recordingStatus,
        recordingFinalized,
        watchAvailable,
        warpgateSessionId: metadata.warpgateSessionId || null,
        hasRecording,
        lastFailure,
        recordingFailures: Array.isArray(metadata.recordingFailures)
          ? metadata.recordingFailures
          : [],

      });

    }


    // ----------------------------------------------
    // NEWEST FIRST
    // ----------------------------------------------

    allowedSessions.sort(
      (a, b) => {

        const aTime =
          new Date(
            a.startedAt || 0
          ).getTime();


        const bTime =
          new Date(
            b.startedAt || 0
          ).getTime();


        return (
          bTime - aTime
        );

      }
    );


    console.log(
      `${requester} can view ${allowedSessions.length} recording(s)`
    );


    return res.json(
      allowedSessions
    );

  }
);


// ==================================================
// GET SESSION METADATA WITH RBAC
// ==================================================

app.get(
  "/api/session-metadata/:sessionId",
  authenticateWarpgateRequest,

  (req, res) => {

    const requester =
      getRequestUsername(
        req
      );


    if (!requester) {

      return res
        .status(401)
        .json({
          error:
            "Authentication required",
        });

    }


    const {
      sessionId
    } =
      req.params;


    if (
      !isValidSessionId(
        sessionId
      )
    ) {

      return res
        .status(400)
        .json({
          error:
            "Invalid session ID",
        });

    }


    const metadata =
      loadMetadata(
        sessionId
      );


    if (!metadata) {

      return res
        .status(404)
        .json({
          error:
            "Session metadata not found",
        });

    }


    if (
      !canViewRecording(
        requester,
        metadata,
        req.warpgateIdentity.applicationRole,
      )
    ) {

      console.log(
        `RBAC DENIED metadata: ${requester} -> ${sessionId}`
      );


      return res
        .status(403)
        .json({
          error:
            "Forbidden",
        });

    }


    return res.json(
      metadata
    );

  }
);


// ==================================================
// GET RECORDING WITH RBAC
// ==================================================

app.get(
  "/api/sessions/:filename",
  authenticateWarpgateRequest,

  (req, res) => {

    const requester =
      getRequestUsername(
        req
      );


    if (!requester) {

      return res
        .status(401)
        .json({
          error:
            "Authentication required",
        });

    }


    const filename =
      req.params.filename;


    const sessionId =
      sessionIdFromFilename(
        filename
      );


    if (!sessionId) {

      return res
        .status(400)
        .json({
          error:
            "Invalid recording filename",
        });

    }


    const recordingPath =
      getRecordingPath(
        sessionId
      );


    if (
      !fs.existsSync(
        recordingPath
      )
    ) {

      return res
        .status(404)
        .json({
          error:
            "Recording not found",
        });

    }


    const metadata =
      loadMetadata(
        sessionId
      );


    if (!metadata) {

      return res
        .status(404)
        .json({
          error:
            "Recording metadata not found",
        });

    }


    if (
      !canViewRecording(
        requester,
        metadata,
        req.warpgateIdentity.applicationRole,
      )
    ) {

      console.log(
        `RBAC DENIED recording: ${requester} -> ${sessionId}`
      );


      return res
        .status(403)
        .json({
          error:
            "Forbidden",
        });

    }

    if (
      !isRecordingFinalized(
        metadata,
        sessions.has(sessionId),
        fs.existsSync(recordingPath),
      )
    ) {
        return res.status(409).json({
          error: "Replay is available only after the recording is stopped and saved",
        });
    }


    console.log(
      `RBAC ALLOWED recording: ${requester} -> ${sessionId}`
    );


    return res.sendFile(
      recordingPath
    );

  }
);


// ==================================================
// START SERVER
// ==================================================

app.use((error, req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body exceeds the allowed size" });
  }
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Request body is not valid JSON" });
  }
  if (error.message === "Origin is not allowed by rrweb CORS policy") {
    return res.status(403).json({ error: "Browser origin is not allowed" });
  }

  console.error("Unhandled rrweb request failure:", error.message);
  return res.status(500).json({ error: "Internal rrweb service error" });
});

app.listen(
  PORT, "127.0.0.1",

  () => {

    console.log(
      `rrweb server running on http://localhost:${PORT}`
    );

  }
);
