import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import rrwebPlayer from "rrweb-player";
import "rrweb-player/dist/style.css";

import { getRrwebRecording } from "../api/recordings";
import DashboardLayout from "../layouts/DashboardLayout";
import "../styles/AdminPages.css";
import "../styles/RecordingReplay.css";
import { getReplayEventTimestamp } from "./recordings-model";

const SESSION_ID_PATTERN = /^session-[A-Za-z0-9_-]+$/;

export default function ReplayPage() {
  const playerContainerRef = useRef(null);
  const playerRef = useRef(null);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get("sessionId") || "";
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const container = playerContainerRef.current;

    async function loadRecording() {
      setLoading(true);
      setError("");

      if (!SESSION_ID_PATTERN.test(sessionId)) {
        setError("The selected recording has an invalid session ID.");
        setLoading(false);
        return;
      }

      try {
        const events = await getRrwebRecording(sessionId, {
          signal: controller.signal,
        });
        if (cancelled) {
          return;
        }
        if (!container) {
          throw new Error("The replay player container is unavailable.");
        }

        playerRef.current?.$destroy();
        container.replaceChildren();
        const player = new rrwebPlayer({
          target: container,
          props: {
            events,
            width: 1100,
            height: 620,
            autoPlay: true,
            showController: true,
          },
        });
        const playerController = container.querySelector(".rr-controller");
        if (!playerController) {
          player.$destroy();
          throw new Error("The replay controls are unavailable.");
        }
        const timestamp = document.createElement("div");
        timestamp.className = "recording-event-timestamp";
        timestamp.setAttribute("aria-live", "polite");
        const label = document.createElement("span");
        label.textContent = "Event time";
        const time = document.createElement("time");
        time.textContent = getReplayEventTimestamp(events) || "Unavailable";
        timestamp.append(label, time);
        playerController.append(timestamp);

        player.addEventListener("ui-update-current-time", ({ payload }) => {
          time.textContent =
            getReplayEventTimestamp(events, payload) || "Unavailable";
        });
        playerRef.current = player;
      } catch (loadError) {
        if (!cancelled) {
          container?.replaceChildren();
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load this recording.",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadRecording();

    return () => {
      cancelled = true;
      controller.abort();
      playerRef.current?.$destroy();
      playerRef.current = null;
      container?.replaceChildren();
    };
  }, [sessionId]);

  return (
    <DashboardLayout>
      <div className="recording-replay-page web-recording-replay-page">
        <div className="admin-page-header">
          <div>
            <h1>Session Replay</h1>
            <p>{sessionId || "Browser session recording"}</p>
          </div>
          <button
            className="admin-action-button"
            onClick={() => navigate("/admin/recordings")}
          >
            Back to Recordings
          </button>
        </div>

        {loading && (
          <div className="recording-replay-state" role="status">
            Loading recording...
          </div>
        )}

        {!loading && error && (
          <div
            className="recording-replay-state error"
            role="alert"
          >
            {error}
          </div>
        )}

        <div
          className="recording-replay-player"
          hidden={loading || Boolean(error)}
        >
          <div ref={playerContainerRef} />
        </div>
      </div>
    </DashboardLayout>
  );
}
