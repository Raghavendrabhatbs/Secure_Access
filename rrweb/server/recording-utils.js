const crypto = require("crypto");

function isValidSessionId(sessionId) {
  return (
    typeof sessionId === "string" &&
    /^session-[A-Za-z0-9_-]+$/.test(sessionId)
  );
}

function isValidVisitId(visitId) {
  return (
    typeof visitId === "string" &&
    /^[A-Za-z0-9_-]{8,128}$/.test(visitId)
  );
}

function isActiveRoleAssignment(roleAssignment) {
  if (
    !roleAssignment ||
    typeof roleAssignment !== "object" ||
    roleAssignment.revoked_at
  ) {
    return false;
  }

  if (!roleAssignment.expires_at) {
    return true;
  }

  const expiresAt = new Date(roleAssignment.expires_at);
  return (
    !Number.isNaN(expiresAt.getTime()) &&
    expiresAt.getTime() > Date.now()
  );
}

function hasActiveTargetRoleAssignment(assignments) {
  return Array.isArray(assignments) && assignments.some(isActiveRoleAssignment);
}

function getRecordingLifecycleStatus(metadata, active, now = Date.now()) {
  if (metadata?.stoppedAt || metadata?.recordingStatus === "stopped") {
    return "stopped";
  }

  if (!active) {
    return "stopped";
  }

  const lastSeen = new Date(metadata?.lastSeenAt || metadata?.startedAt || 0);
  if (
    Number.isNaN(lastSeen.getTime()) ||
    now - lastSeen.getTime() > 90_000
  ) {
    return "stopped";
  }

  if (metadata?.recordingStatus === "failed") {
    return "stopped";
  }

  return "recording";
}

function isRecordingFinalized(metadata, active, hasRecording) {
  return Boolean(
    metadata?.stoppedAt &&
      metadata?.recordingStatus === "stopped" &&
      !active &&
      hasRecording,
  );
}

function isValidRecordingFailure(stage, httpStatus) {
  return (
    ["token", "start", "upload", "heartbeat", "stop"].includes(stage) &&
    (httpStatus === null ||
      httpStatus === undefined ||
      (Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599))
  );
}

function appendRecordingFailure(metadata, stage, httpStatus, now = new Date()) {
  const timestamp = now.toISOString();
  const failure = {
    timestamp,
    stage,
    httpStatus: httpStatus ?? null,
    message: httpStatus
      ? `Recording ${stage} request failed with HTTP ${httpStatus}`
      : `Recording ${stage} request failed before a response was received`,
    resolvedAt: null,
    resolution: null,
  };
  metadata.recordingFailures = Array.isArray(metadata.recordingFailures)
    ? metadata.recordingFailures
    : [];

  const isDuplicate = metadata.recordingFailures.some((existing) => {
    if (
      existing.resolvedAt ||
      existing.stage !== failure.stage ||
      existing.httpStatus !== failure.httpStatus
    ) {
      return false;
    }
    const existingTime = new Date(existing.timestamp).getTime();
    return (
      Number.isFinite(existingTime) &&
      now.getTime() >= existingTime &&
      now.getTime() - existingTime < 60_000
    );
  });
  if (!isDuplicate) {
    metadata.recordingFailures.push(failure);
    metadata.recordingFailures = metadata.recordingFailures.slice(-20);
    metadata.lastFailure = failure;
  }
  return isDuplicate;
}

function canControlRecordingByPolicy(
  username,
  target,
  authenticationType,
) {
  const normalizedUsername = typeof username === "string" ? username.trim() : "";
  const normalizedTarget = typeof target === "string" ? target.trim() : "";
  const normalizedAuthenticationType = typeof authenticationType === "string"
    ? authenticationType.trim()
    : "";

  if (
    !normalizedUsername ||
    normalizedUsername.toLowerCase() === "unknown" ||
    !normalizedTarget ||
    !["user", "ticket"].includes(normalizedAuthenticationType)
  ) {
    return false;
  }

  // Warpgate issues these signed claims only after authorizing this target.
  return true;
}

function canWriteRecordingByApplicationRole(applicationRole) {
  const normalizedApplicationRole = typeof applicationRole === "string"
    ? applicationRole.trim()
    : "";
  return ["admin", "developer"].includes(normalizedApplicationRole);
}

function canViewRecordingByPolicy(
  username,
  applicationRole,
  metadata,
  authorizedTargetNames = [],
) {
  const normalizedUsername = typeof username === "string" ? username.trim() : "";
  const normalizedApplicationRole = typeof applicationRole === "string"
    ? applicationRole.trim()
    : "";

  if (
    !normalizedUsername ||
    normalizedUsername.toLowerCase() === "unknown" ||
    !["admin", "developer", "auditor_viewer"].includes(normalizedApplicationRole) ||
    !metadata ||
    typeof metadata !== "object" ||
    !Array.isArray(authorizedTargetNames)
  ) {
    return false;
  }

  if (normalizedApplicationRole === "admin") {
    return true;
  }

  const metadataUsername = typeof metadata.username === "string"
    ? metadata.username.trim()
    : "";
  if (!metadataUsername || metadataUsername.toLowerCase() === "unknown") {
    return false;
  }

  const recordingTargets = [
    metadata.target,
    ...(Array.isArray(metadata.targets) ? metadata.targets : []),
  ]
    .filter((target) => typeof target === "string")
    .map((target) => target.trim())
    .filter(Boolean);
  if (recordingTargets.length === 0) {
    return false;
  }

  if (normalizedApplicationRole === "auditor_viewer") {
    return true;
  }

  const targetIsAuthorized = recordingTargets.some((target) =>
    authorizedTargetNames.some(
      (authorizedTarget) =>
        typeof authorizedTarget === "string" &&
        authorizedTarget.trim().toLowerCase() === target.toLowerCase(),
    ),
  );
  if (!targetIsAuthorized) {
    return false;
  }

  return metadataUsername.toLowerCase() === normalizedUsername.toLowerCase();
}

function verifyRecordingToken(token, signingSecret) {
  if (typeof token !== "string" || !signingSecret) {
    return null;
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }

  const [encodedPayload, providedSignature] = parts;
  const expectedSignature = crypto
    .createHmac("sha256", signingSecret)
    .update(encodedPayload)
    .digest("base64url");
  const providedBuffer = Buffer.from(providedSignature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    providedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(providedBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    );
    const normalizedUsername = typeof payload.username === "string"
      ? payload.username.trim()
      : "";
    const normalizedTarget = typeof payload.target === "string"
      ? payload.target.trim()
      : "";
    const normalizedAuthenticationType = typeof payload.authenticationType === "string"
      ? payload.authenticationType.trim()
      : "";

    if (
      !normalizedUsername ||
      normalizedUsername.toLowerCase() === "unknown" ||
      !normalizedTarget ||
      (payload.warpgateUserId !== undefined &&
        payload.warpgateUserId !== null &&
        typeof payload.warpgateUserId !== "string") ||
      (payload.warpgateSessionId !== undefined &&
        payload.warpgateSessionId !== null &&
        typeof payload.warpgateSessionId !== "string") ||
      !["user", "ticket"].includes(normalizedAuthenticationType) ||
      !isValidSessionId(payload.recordingSessionId) ||
      !Number.isSafeInteger(payload.expiresAt) ||
      Date.now() >= payload.expiresAt
    ) {
      return null;
    }

    payload.username = normalizedUsername;
    payload.target = normalizedTarget;
    payload.authenticationType = normalizedAuthenticationType;
    return payload;
  } catch {
    return null;
  }
}

function authorizeRecordingToken(authorization, signingSecret, canControl) {
  if (
    typeof authorization !== "string" ||
    !authorization.startsWith("Bearer ")
  ) {
    return {
      statusCode: 401,
      error: "Recording authentication required",
    };
  }

  const identity = verifyRecordingToken(
    authorization.slice("Bearer ".length),
    signingSecret,
  );
  if (!identity) {
    return {
      statusCode: 401,
      error: "Invalid or expired recording token",
    };
  }

  if (
    !canControl(
      identity.username,
      identity.target,
      identity.authenticationType,
    )
  ) {
    return {
      statusCode: 403,
      error: "Recording token identity is not authorized",
    };
  }

  return { statusCode: 200, identity };
}

function isValidRrwebEvent(event) {
  return (
    event !== null &&
    typeof event === "object" &&
    !Array.isArray(event) &&
    Number.isSafeInteger(event.type) &&
    Number.isFinite(event.timestamp) &&
    event.data !== null &&
    typeof event.data === "object" &&
    !Array.isArray(event.data)
  );
}

function isValidEventBatch(batch) {
  return (
    batch !== null &&
    typeof batch === "object" &&
    !Array.isArray(batch) &&
    isValidVisitId(batch.batchId) &&
    Array.isArray(batch.events) &&
    batch.events.length > 0 &&
    batch.events.length <= 5000 &&
    batch.events.every(isValidRrwebEvent)
  );
}

function recordingIdentityMatchesMetadata(identity, metadata, sessionId) {
  const metadataUsername = typeof metadata?.username === "string"
    ? metadata.username.trim()
    : "";
  const identityUsername = typeof identity?.username === "string"
    ? identity.username.trim()
    : "";
  const metadataTarget = typeof metadata?.target === "string"
    ? metadata.target.trim()
    : "";
  const identityTarget = typeof identity?.target === "string"
    ? identity.target.trim()
    : "";
  const legacyTargetMatch =
    !metadataTarget &&
    (Array.isArray(metadata?.targets)
      ? metadata.targets
      : []
    ).some(
      (target) => typeof target === "string" && target.trim() === identityTarget,
    );
  return (
    identity !== null &&
    typeof identity === "object" &&
    isValidSessionId(sessionId) &&
    identity?.recordingSessionId === sessionId &&
    metadataUsername === identityUsername &&
    metadata?.authenticationType === identity.authenticationType &&
    (metadataTarget === identityTarget || legacyTargetMatch) &&
    (identity.warpgateUserId == null ||
      metadata?.warpgateUserId === identity.warpgateUserId) &&
    (identity.warpgateSessionId == null ||
      metadata?.warpgateSessionId === identity.warpgateSessionId)
  );
}

function canWatchActiveWebRecording(
  applicationRole,
  recordingSessionId,
  metadata,
  warpgateSession,
  currentWarpgateUserId,
  hasLiveRecording,
) {
  let targetSnapshot = warpgateSession?.target_snapshot;
  if (typeof targetSnapshot === "string") {
    try {
      targetSnapshot = JSON.parse(targetSnapshot);
    } catch {
      return false;
    }
  }

  const metadataUsername = typeof metadata?.username === "string"
    ? metadata.username.trim()
    : "";
  const metadataTarget = typeof metadata?.target === "string"
    ? metadata.target.trim()
    : "";

  return (
    applicationRole === "admin" &&
    isValidSessionId(recordingSessionId) &&
    metadata?.sessionId === recordingSessionId &&
    typeof metadata.warpgateSessionId === "string" &&
    metadata.warpgateSessionId === warpgateSession?.id &&
    typeof metadata.warpgateUserId === "string" &&
    metadata.warpgateUserId === currentWarpgateUserId &&
    metadataUsername.toLowerCase() ===
      String(warpgateSession?.username || "").trim().toLowerCase() &&
    metadataTarget === String(targetSnapshot?.name || "").trim() &&
    ["HTTP", "HTTPS"].includes(
      String(warpgateSession?.protocol || "").toUpperCase(),
    ) &&
    warpgateSession?.ended === null &&
    metadata.recordingStatus !== "failed" &&
    metadata.recordingStatus !== "stopped" &&
    hasLiveRecording === true
  );
}

function redactPageUrl(value) {
  if (typeof value !== "string") {
    return null;
  }

  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (key === "warpgate-target" || key === "warpgate-ticket") {
        url.searchParams.delete(key);
      } else if (
        /auth|token|secret|password|passwd|code|key|session|ticket|signature|credential/i.test(
          key,
        )
      ) {
        url.searchParams.set(key, "[redacted]");
      }
    }
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

function appendIdempotentBatch(sessionEvents, metadata, batchId, events) {
  metadata.batchIds = Array.isArray(metadata.batchIds)
    ? metadata.batchIds
    : [];
  if (metadata.batchIds.includes(batchId)) {
    return false;
  }

  sessionEvents.push(...events);
  metadata.batchIds.push(batchId);
  metadata.eventCount = sessionEvents.length;
  return true;
}

module.exports = {
  appendIdempotentBatch,
  authorizeRecordingToken,
  appendRecordingFailure,
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
  isValidRrwebEvent,
  isValidSessionId,
  isValidVisitId,
  recordingIdentityMatchesMetadata,
  redactPageUrl,
  verifyRecordingToken,
};
