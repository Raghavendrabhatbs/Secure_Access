const RRWEB_API = "/@warpgate/rrweb";

const SESSION_ID_PATTERN = /^session-[A-Za-z0-9_-]+$/;

export function canReplayRecording(recording) {
  const sessionId =
    recording?.sessionId || recording?.file?.replace(/\.json$/, "");
  return (
    recording?.hasRecording !== false &&
    Number(recording?.eventCount) > 1 &&
    SESSION_ID_PATTERN.test(sessionId || "")
  );
}

export function validateRrwebEvents(events) {
  if (!Array.isArray(events)) {
    throw new Error("The recording response is not an event array.");
  }
  if (events.length < 2) {
    throw new Error("The recording contains too few events to replay.");
  }
  if (
    !events.every(
      (event) =>
        event !== null &&
        typeof event === "object" &&
        !Array.isArray(event) &&
        Number.isSafeInteger(event.type) &&
        event.type >= 0 &&
        event.type <= 6 &&
        Number.isFinite(event.timestamp) &&
        event.data !== null &&
        typeof event.data === "object" &&
        !Array.isArray(event.data),
    )
  ) {
    throw new Error("The recording contains invalid rrweb events.");
  }
  if (!events.some((event) => event.type === 2)) {
    throw new Error("The recording has no full snapshot and cannot be replayed.");
  }

  return events;
}

async function responseError(response, action) {
  let message = "";
  try {
    const body = await response.json();
    if (typeof body.error === "string") {
      message = body.error;
    }
  } catch {
    // Use the HTTP status when the server response is not JSON.
  }
  return new Error(
    message || `${action} failed with HTTP ${response.status}.`,
  );
}

export async function getRrwebRecordings() {
  console.log(
    "[rrweb-api] Fetching recording list..."
  );

  const response = await fetch(
    `${RRWEB_API}/api/sessions`,
    {
      method: "GET",
      credentials: "include",
    }
  );

  console.log(
    "[rrweb-api] Recording list response:",
    response.status
  );

  if (!response.ok) {
    throw await responseError(response, "Loading the recording list");
  }

  const recordings = await response.json();
  if (!Array.isArray(recordings)) {
    throw new Error("The recording list response is invalid.");
  }
  return recordings;
}


export async function getRrwebRecording(
  sessionId,
  { signal } = {},
) {
  if (
    typeof sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(sessionId)
  ) {
    throw new Error("The selected recording has an invalid session ID.");
  }

  const url =
    `${RRWEB_API}/api/sessions/${encodeURIComponent(
      `${sessionId}.json`,
    )}`;

  console.log(
    "[rrweb-api] Starting recording fetch:",
    url
  );


  const response = await fetch(
    url,
    {
      method: "GET",
      credentials: "include",
      signal,
    }
  );


  console.log(
    "[rrweb-api] Recording response:",
    response.status,
    response.statusText
  );


  if (!response.ok) {
    throw await responseError(response, "Loading the recording");
  }


  console.log(
    "[rrweb-api] Reading recording JSON..."
  );


  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The saved recording is not valid JSON.");
  }


  console.log(
    "[rrweb-api] Recording JSON loaded:",
    Array.isArray(data)
      ? `${data.length} events`
      : typeof data
  );


  return validateRrwebEvents(data);
}


export async function getRrwebRecordingMetadata(
  sessionId
) {
  const url =
    `${RRWEB_API}/api/session-metadata/${encodeURIComponent(
      sessionId
    )}`;


  console.log(
    "[rrweb-api] Fetching metadata:",
    url
  );


  const response = await fetch(
    url,
    {
      method: "GET",
      credentials: "include",
    }
  );


  console.log(
    "[rrweb-api] Metadata response:",
    response.status
  );


  if (!response.ok) {
    throw new Error(
      `Failed to fetch recording metadata: ${response.status}`
    );
  }

  return response.json();
}