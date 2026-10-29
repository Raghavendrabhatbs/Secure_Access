import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import rrwebPlayer from "rrweb-player";
import "rrweb-player/dist/style.css";

import { useAppRole } from "../auth/useAppRole";
import { logSecureAccessEvent } from "../api/audit";
import DashboardLayout from "../layouts/DashboardLayout";
import WarpgateAdminFrame from "../components/WarpgateAdminFrame";
import "../styles/AdminPages.css";
import "../styles/RecordingReplay.css";

const RRWEB_API = "/@warpgate/rrweb";
const WEB_SESSION_ID_PATTERN = /^session-[A-Za-z0-9_-]+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default function WatchPage() {
  const [searchParams] = useSearchParams();
  const { role } = useAppRole();
  const protocol = (searchParams.get("protocol") || "").toUpperCase();
  const sessionId = searchParams.get("sessionId") || "";
  const warpgateSessionId = searchParams.get("warpgateSessionId") || "";
  const recordingId = searchParams.get("recordingId") || "";

  if (role !== "admin") {
    return null;
  }

  return (
    <WatchSession
      key={`${protocol}:${sessionId}:${warpgateSessionId}:${recordingId}`}
      protocol={protocol}
      sessionId={sessionId}
      warpgateSessionId={warpgateSessionId}
      recordingId={recordingId}
    />
  );
}

function WatchSession({ protocol, sessionId, warpgateSessionId, recordingId }) {
  const playerContainerRef = useRef(null);
  const playerRef = useRef(null);
  const lastSequenceRef = useRef(-1);
  const navigate = useNavigate();
  const [status, setStatus] = useState("Connecting to the live session...");
  const [error, setError] = useState("");
  const [isComplete, setIsComplete] = useState(false);
  const invalidSession =
    protocol === "SSH"
      ? !UUID_PATTERN.test(recordingId)
      : protocol !== "WEB" ||
        !WEB_SESSION_ID_PATTERN.test(sessionId) ||
        !UUID_PATTERN.test(warpgateSessionId);
  const displayedError =
    invalidSession
      ? protocol === "SSH"
        ? "The selected SSH recording has an invalid identifier."
        : "The selected live session has invalid identifiers."
      : error;

  useEffect(() => {
    lastSequenceRef.current = -1;
    playerRef.current?.$destroy();
    playerRef.current = null;

    if (protocol === "SSH" || invalidSession) {
      return undefined;
    }

    let cancelled = false;
    const events = [];
    const container = playerContainerRef.current;
    const source = new EventSource(
      `${RRWEB_API}/api/sessions/${encodeURIComponent(sessionId)}/watch`,
      { withCredentials: true },
    );

    const closeSource = () => source.close();
    const fail = (message) => {
      if (cancelled) return;
      setError(message);
      setStatus("");
      closeSource();
    };

    source.addEventListener("session", (message) => {
      try {
        const details = JSON.parse(message.data);
        if (
          details.sessionId !== sessionId ||
          details.warpgateSessionId !== warpgateSessionId
        ) {
          fail("The server returned a different recording session.");
          return;
        }
        setStatus("Live session connected");
        void logSecureAccessEvent("recordings", "recording.watch.opened", {
          sessionId,
          warpgateSessionId,
          protocol: "WEB",
        }).catch((auditError) =>
          console.error("Unable to audit the web Watch action:", auditError),
        );
      } catch {
        fail("The live session details could not be read.");
      }
    });

    source.addEventListener("rrweb", (message) => {
      try {
        const item = JSON.parse(message.data);
        if (
          !Number.isSafeInteger(item.sequence) ||
          item.sequence <= lastSequenceRef.current
        ) {
          return;
        }
        lastSequenceRef.current = item.sequence;

        const event = item.event;
        if (
          !event ||
          !Number.isSafeInteger(event.type) ||
          !Number.isFinite(event.timestamp) ||
          event.data === null ||
          typeof event.data !== "object"
        ) {
          fail("The live recording contained an invalid event.");
          return;
        }

        if (!playerRef.current) {
          events.push(event);
          if (event.type !== 2) return;
          if (!container) {
            fail("The live session viewer is unavailable.");
            return;
          }
          playerRef.current = new rrwebPlayer({
            target: container,
            props: {
              events,
              width: 1100,
              height: 620,
              autoPlay: true,
              showController: true,
            },
          });
          setStatus("Live session connected");
          return;
        }

        playerRef.current.addEvent(event);
      } catch {
        fail("A live recording event could not be processed.");
      }
    });

    source.addEventListener("state", (message) => {
      try {
        const { state } = JSON.parse(message.data);
        if (state === "completed") {
          setIsComplete(true);
          setStatus("Session ended. The recording is finalized.");
          closeSource();
        } else if (state === "finalization-pending") {
          fail("The session ended; recording finalization is still pending.");
        } else if (state === "authorization-revoked") {
          fail("Admin authorization is no longer valid.");
        } else {
          fail("Live session is unavailable or could not be verified.");
        }
      } catch {
        fail("The live session status could not be read.");
      }
    });

    source.onerror = () => {
      if (cancelled || source.readyState === EventSource.CLOSED) return;
      setStatus("Connection interrupted. Reconnecting...");
    };

    return () => {
      cancelled = true;
      closeSource();
      playerRef.current?.$destroy();
      playerRef.current = null;
      container?.replaceChildren();
    };
  }, [invalidSession, protocol, recordingId, sessionId, warpgateSessionId]);

  useEffect(() => {
    if (protocol === "SSH" && UUID_PATTERN.test(recordingId)) {
      void logSecureAccessEvent("recordings", "recording.watch.opened", {
        sessionId,
        protocol: "SSH",
      }).catch((auditError) =>
        console.error("Unable to audit the SSH Watch action:", auditError),
      );
    }
  }, [protocol, recordingId, sessionId]);

  const sshSrc =
    protocol === "SSH" && UUID_PATTERN.test(recordingId)
      ? `/@warpgate/admin#/status/recordings/${encodeURIComponent(recordingId)}/watch`
      : "";

  return (
    <DashboardLayout>
      <div className="recording-replay-page web-recording-replay-page">
        <div className="admin-page-header">
          <div>
            <h1>Live Session Watch</h1>
            <p>
              {protocol === "SSH"
                ? `SSH session ${sessionId || recordingId}`
                : `Web session ${sessionId}`}
            </p>
          </div>
          <button
            className="admin-action-button"
            onClick={() => navigate("/admin/sessions")}
            type="button"
          >
            Back to Sessions
          </button>
        </div>

        {status && protocol !== "SSH" && !displayedError && (
          <div className="recording-replay-state" role="status">
            {status}
          </div>
        )}
        {displayedError && (
          <div className="recording-replay-state error" role="alert">
            {displayedError}
          </div>
        )}
        {isComplete && (
          <div className="admin-page-state">
            Replay is now available from the finalized recording.
          </div>
        )}

        {protocol === "SSH" && sshSrc && !displayedError && (
          <section className="admin-panel warpgate-admin-embed watch-ssh-panel">
            <WarpgateAdminFrame
              className="warpgate-admin-embed-frame"
              src={sshSrc}
              title="SecureAccess live SSH session"
            />
          </section>
        )}

        {protocol === "WEB" && (
          <div
            className="recording-replay-player"
            hidden={Boolean(displayedError)}
          >
            <div ref={playerContainerRef} />
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
