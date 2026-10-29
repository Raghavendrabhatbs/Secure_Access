import assert from "node:assert/strict";
import test from "node:test";

import {
  compareRecordingsNewestFirst,
  getRecordingDisplayId,
  getReplayEventTimestamp,
  normalizeRecording,
} from "./recordings-model.js";

test("formats SSH display IDs with session ID, username, and IST timestamp", () => {
  assert.equal(
    getRecordingDisplayId({
      protocol: "SSH",
      username: "qa/user",
      startedAt: "2026-10-19T14:36:07.000+05:30",
      originalSessionId: "ssh-session-123",
    }),
    "SSH-ssh-session-123-qa_user-20261019-143607IST",
  );
});

test("formats Web display IDs and preserves the canonical Web replay ID", () => {
  const recording = normalizeRecording(
    {
      sessionId: "session-web_123",
      username: "operator",
      startedAt: "2026-10-19T09:00:00Z",
      eventCount: 10,
    },
    "WEB",
  );
  assert.equal(
    recording.displayId,
    "web-session-session-web_123-operator-20261019-143000IST",
  );
  assert.equal(recording.originalSessionId, "session-web_123");
  assert.equal(recording.canReplay, true);
  assert.equal(recording.recordingStatus, "stopped");
});

test("shows active Web recording state and collapses other states to stopped", () => {
  const activeRecording = normalizeRecording(
    {
      sessionId: "session-web_active",
      recordingStatus: "recording",
      eventCount: 0,
    },
    "WEB",
  );
  const failedRecording = normalizeRecording(
    {
      sessionId: "session-web_failed",
      recordingStatus: "failed",
      eventCount: 0,
    },
    "WEB",
  );

  assert.equal(activeRecording.recordingStatus, "recording");
  assert.equal(activeRecording.canReplay, false);
  assert.equal(failedRecording.recordingStatus, "stopped");
});

test("only exposes Web replay after backend finalization and Watch for verified live rows", () => {
  const active = normalizeRecording(
    {
      sessionId: "session-web_active",
      recordingStatus: "recording",
      recordingFinalized: false,
      watchAvailable: true,
      eventCount: 12,
    },
    "WEB",
  );
  const pending = normalizeRecording(
    {
      sessionId: "session-web_pending",
      recordingStatus: "stopped",
      recordingFinalized: false,
      eventCount: 12,
    },
    "WEB",
  );

  assert.equal(active.watchAvailable, true);
  assert.equal(active.canReplay, false);
  assert.equal(pending.watchAvailable, false);
  assert.equal(pending.canReplay, false);
});

test("sorts active recordings by latest activity rather than original start time", () => {
  const recordings = [
    normalizeRecording(
      {
        sessionId: "session-long",
        startedAt: "2026-10-20T07:45:40.646Z",
        lastSeenAt: "2026-10-20T14:56:01.965Z",
      },
      "WEB",
    ),
    normalizeRecording(
      {
        sessionId: "session-new",
        startedAt: "2026-10-20T13:00:00.000Z",
        lastSeenAt: "2026-10-20T13:01:00.000Z",
      },
      "WEB",
    ),
  ].sort(compareRecordingsNewestFirst);

  assert.deepEqual(
    recordings.map(({ originalSessionId }) => originalSessionId),
    ["session-long", "session-new"],
  );
});

test("uses explicit placeholders when display identifier metadata is unavailable", () => {
  assert.equal(
    getRecordingDisplayId({
      protocol: "WEB",
    }),
    "web-session-session-ID-unavailable-username-unavailable-date-time-unavailable",
  );
});

test("maps replay offset to the absolute event timestamp in IST", () => {
  const events = [
    { timestamp: Date.parse("2026-10-19T09:00:00.000Z") },
    { timestamp: Date.parse("2026-10-19T09:00:08.000Z") },
  ];

  assert.equal(
    getReplayEventTimestamp(events, 8_000),
    "19 Oct 2026, 02:30:08 pm IST",
  );
  assert.equal(getReplayEventTimestamp([], 0), null);
});

test("normalizes SSH replay through its native Warpgate player route", () => {
  const recording = normalizeRecording(
    {
      id: "c5db5b03-1d75-4a8b-9d72-b9d77d3c33e1",
      sessionId: "e0e11e1a-3d83-4ae4-b351-a705de1e3a91",
      recordingStatus: "completed",
      started: "2026-10-19T09:00:00Z",
      ended: "2026-10-19T09:02:00Z",
    },
    "SSH",
  );
  assert.equal(recording.canReplay, true);
  assert.equal(
    recording.playbackUrl,
    "/@warpgate/admin#/status/recordings/c5db5b03-1d75-4a8b-9d72-b9d77d3c33e1",
  );
  assert.equal(recording.recordingStatus, "stopped");
  assert.equal(recording.durationMs, 120_000);
  assert.equal(recording.storageBytes, undefined);
  assert.equal(
    recording.displayId,
    "SSH-c5db5b03-1d75-4a8b-9d72-b9d77d3c33e1-username-unavailable-20261019-143000IST",
  );
});

test("allows replay of SSH recordings when the session ended before recording closure", () => {
  const recording = normalizeRecording(
    {
      id: "c5db5b03-1d75-4a8b-9d72-b9d77d3c33e1",
      sessionId: "e0e11e1a-3d83-4ae4-b351-a705de1e3a91",
      recordingStatus: "incomplete",
      started: "2026-10-19T09:00:00Z",
      ended: null,
    },
    "SSH",
  );
  assert.equal(recording.recordingFinalized, true);
  assert.equal(recording.canReplay, true);
  assert.equal(recording.recordingStatus, "stopped");
});

test("sorts recordings newest first with deterministic ID tie-breaking", () => {
  const sorted = [
    { id: "WEB:older", startedAt: "2026-10-18T00:00:00Z" },
    { id: "SSH:b", startedAt: "2026-10-19T00:00:00Z" },
    { id: "SSH:a", startedAt: "2026-10-19T00:00:00Z" },
  ].sort(compareRecordingsNewestFirst);
  assert.deepEqual(sorted.map(({ id }) => id), ["SSH:a", "SSH:b", "WEB:older"]);
});
