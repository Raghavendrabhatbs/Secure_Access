import { canReplayRecording } from "../api/recordings.js";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function istDisplayTimestamp(value) {
  const date = new Date(value || "");
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const values = Object.fromEntries(
    parts
      .filter((part) => part.type !== "literal")
      .map(({ type, value }) => [type, value]),
  );
  return `${values.year}${values.month}${values.day}-${values.hour}${values.minute}${values.second}IST`;
}

export function getRecordingDisplayId({
  protocol,
  username,
  startedAt,
  originalSessionId,
}) {
  const prefix = protocol === "SSH" ? "SSH" : "web-session";
  const sessionId = originalSessionId || "session-ID-unavailable";
  const safeUsername = String(username || "username-unavailable")
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "_");
  const timestamp = istDisplayTimestamp(startedAt) || "date-time-unavailable";
  return `${prefix}-${sessionId}-${safeUsername}-${timestamp}`;
}

export function getReplayEventTimestamp(events, timeOffset = 0) {
  const firstEventTimestamp = events?.[0]?.timestamp;
  if (
    !Number.isFinite(firstEventTimestamp) ||
    !Number.isFinite(timeOffset)
  ) {
    return null;
  }

  const date = new Date(firstEventTimestamp + Math.max(0, timeOffset));
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return new Intl.DateTimeFormat("en-IN", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h12",
    timeZone: "Asia/Kolkata",
    timeZoneName: "short",
  }).format(date);
}

export function normalizeRecording(recording, protocol) {
  if (protocol === "WEB") {
    const originalSessionId =
      recording?.sessionId || recording?.file?.replace(/\.json$/, "");
    const recordingFinalized =
      recording?.recordingFinalized === true ||
      (recording?.recordingFinalized == null &&
        recording?.recordingStatus !== "recording");
    const normalized = {
      id: `WEB:${originalSessionId}`,
      protocol,
      originalSessionId,
      sessionId: originalSessionId,
      username: recording?.username || null,
      userId: recording?.userId || null,
      target: recording?.target || null,
      startedAt: recording?.startedAt || null,
      lastSeenAt: recording?.lastSeenAt || null,
      lastActivityAt:
        recording?.lastSeenAt || recording?.startedAt || null,
      durationMs: recording?.durationMs,
      eventCount: recording?.eventCount,
      storageBytes: recording?.storageBytes,
      recordingStatus:
        recording?.recordingStatus === "recording" ? "recording" : "stopped",
      firstPageUrl: recording?.firstPageUrl || null,
      lastPageUrl: recording?.lastPageUrl || null,
      lastFailure: recording?.lastFailure || null,
      recordingFinalized,
      watchAvailable: recording?.watchAvailable === true,
      warpgateSessionId: recording?.warpgateSessionId || null,
      canReplay: canReplayRecording(recording) && recordingFinalized,
    };
    normalized.displayId = getRecordingDisplayId(normalized);
    return normalized;
  }

  const startedAt = recording?.started || null;
  const endedAt = recording?.ended || null;
  const startedMs = new Date(startedAt || "").getTime();
  const endedMs = new Date(endedAt || "").getTime();
  const durationMs =
    Number.isFinite(startedMs) && Number.isFinite(endedMs)
      ? Math.max(0, endedMs - startedMs)
      : null;
  const originalSessionId = recording?.id || null;
  const recordingFinalized =
    ["completed", "incomplete"].includes(recording?.recordingStatus) ||
    (recording?.recordingStatus == null && Boolean(endedAt));
  const normalized = {
    id: `SSH:${originalSessionId}`,
    protocol,
    originalSessionId,
    sessionId: recording?.sessionId || originalSessionId,
    username: recording?.username || null,
    userId: recording?.userId || null,
    target: recording?.target || null,
    startedAt,
    lastActivityAt: endedAt || startedAt,
    durationMs,
    eventCount: null,
    storageBytes: recording?.storageBytes,
    recordingStatus:
      recording?.recordingStatus === "recording" ? "recording" : "stopped",
    recordingFinalized,
    watchAvailable:
      recording?.recordingStatus === "recording" &&
      recording?.ended == null &&
      Boolean(recording?.sessionId),
    firstPageUrl: null,
    lastPageUrl: null,
    lastFailure: null,
    playbackUrl:
      UUID_PATTERN.test(originalSessionId || "")
        ? `/@warpgate/admin#/status/recordings/${encodeURIComponent(originalSessionId)}`
        : null,
    canReplay:
      recordingFinalized && UUID_PATTERN.test(originalSessionId || ""),
  };
  normalized.displayId = getRecordingDisplayId(normalized);
  return normalized;
}

export function compareRecordingsNewestFirst(left, right) {
  const leftTime = new Date(
    left.lastActivityAt || left.lastSeenAt || left.endedAt || left.startedAt || "",
  ).getTime();
  const rightTime = new Date(
    right.lastActivityAt || right.lastSeenAt || right.endedAt || right.startedAt || "",
  ).getTime();
  const safeLeftTime = Number.isFinite(leftTime) ? leftTime : 0;
  const safeRightTime = Number.isFinite(rightTime) ? rightTime : 0;
  return safeRightTime - safeLeftTime || left.id.localeCompare(right.id);
}
