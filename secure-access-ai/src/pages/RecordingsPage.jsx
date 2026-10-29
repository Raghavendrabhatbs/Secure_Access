import {
  RefreshCw,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAppRole } from "../auth/useAppRole";

import {
  getRrwebRecordings,
} from "../api/recordings";
import {
  getWarpgateRecordings,
} from "../api/warpgate";
import { logSecureAccessEvent } from "../api/audit";
import DashboardLayout from "../layouts/DashboardLayout";
import "../styles/AdminPages.css";
import "../styles/RecordingReplay.css";
import {
  compareRecordingsNewestFirst,
  normalizeRecording,
} from "./recordings-model";

const PAGE_SIZE = 10;
const VALID_PROTOCOLS = new Set(["ALL", "SSH", "WEB"]);
const IST_OFFSET_MINUTES = 5 * 60 + 30;

function formatDate(value) {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        timeZoneName: "short",
      });
}

function getIstDayBoundary(value, nextDay = false) {
  if (!value) {
    return nextDay ? Infinity : -Infinity;
  }
  const [year, month, day] = value.split("-").map(Number);
  return Date.UTC(year, month - 1, day + Number(nextDay)) -
    IST_OFFSET_MINUTES * 60_000;
}

function formatDuration(recording, now) {
  let milliseconds = Number(recording.durationMs);
  if (
    !Number.isFinite(milliseconds) &&
    recording.recordingStatus === "recording"
  ) {
    const startedAt = new Date(recording.startedAt || "").getTime();
    milliseconds = Number.isFinite(startedAt)
      ? Math.max(0, now - startedAt)
      : NaN;
  }
  if (!Number.isFinite(milliseconds)) {
    return "—";
  }
  const totalSeconds = Math.floor(milliseconds / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return hours
    ? `${hours}h ${minutes}m`
    : minutes
      ? `${minutes}m ${seconds}s`
      : `${seconds}s`;
}

function statusLabel(status) {
  return status === "recording" ? "Recording" : "Stopped";
}

function RecordingRows({ recordings, now, canWatch, onReplay, onWatch }) {
  return recordings.map((recording) => (
    <tr key={recording.id}>
      <td>
        <div className="recording-session-cell">
          <strong title={recording.displayId}>{recording.displayId}</strong>
          <span>
            {recording.lastFailure?.message ||
              recording.firstPageUrl ||
              recording.originalSessionId ||
              "Recording identifier unavailable"}
          </span>
        </div>
      </td>
      <td>{recording.username || "—"}</td>
      <td>{recording.target || "—"}</td>
      <td>{recording.protocol}</td>
      <td>
        <div className="recording-date-cell">
          <strong>{formatDate(recording.lastActivityAt || recording.startedAt)}</strong>
          {recording.startedAt &&
            recording.lastActivityAt !== recording.startedAt && (
              <span>Started {formatDate(recording.startedAt)}</span>
            )}
        </div>
      </td>
      <td>
        <span className={`recording-status ${recording.recordingStatus}`}>
          {statusLabel(recording.recordingStatus)}
        </span>
      </td>
      <td>{formatDuration(recording, now)}</td>
      <td>{recording.eventCount ?? "—"}</td>
      <td>
        {canWatch && recording.watchAvailable ? (
          <button
            className="admin-action-button"
            onClick={() => onWatch(recording)}
            type="button"
          >
            Watch
          </button>
        ) : recording.canReplay ? (
          <button
            className="admin-action-button"
            onClick={() => onReplay(recording)}
            type="button"
          >
            Replay
          </button>
        ) : (
          <span className="table-muted">
            {recording.recordingStatus === "recording"
              ? "Live session"
              : recording.recordingFinalized
                ? "Replay unavailable"
                : "Finalization pending"}
          </span>
        )}
      </td>
    </tr>
  ));
}

export default function RecordingsPage() {
  const { role: applicationRole } = useAppRole();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedProtocol = (searchParams.get("protocol") || "ALL").toUpperCase();
  const protocolFilter = VALID_PROTOCOLS.has(requestedProtocol)
    ? requestedProtocol
    : "ALL";
  const [recordings, setRecordings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [loadErrors, setLoadErrors] = useState({ web: "", ssh: "" });
  const [search, setSearch] = useState("");
  const [usernameFilter, setUsernameFilter] = useState("");
  const [targetFilter, setTargetFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [now, setNow] = useState(0);

  const loadRecordings = useCallback(async (background = false) => {
    if (background) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError("");

    try {
      const [webResult, sshResult] = await Promise.allSettled([
        getRrwebRecordings(),
        getWarpgateRecordings({ applicationRole }),
      ]);
      setLoadErrors({
        web: webResult.status === "rejected"
          ? `Web recordings could not be loaded: ${
              webResult.reason instanceof Error
                ? webResult.reason.message
                : "Unknown error."
            }`
          : "",
        ssh: sshResult.status === "rejected"
          ? `SSH recordings could not be loaded: ${
              sshResult.reason instanceof Error
                ? sshResult.reason.message
                : "Unknown error."
            }`
          : "",
      });
      if (webResult.status === "rejected" && sshResult.status === "rejected") {
        throw new AggregateError(
          [webResult.reason, sshResult.reason],
          "Unable to load either SSH or Web recordings.",
        );
      }
      if (webResult.status === "fulfilled" && !Array.isArray(webResult.value)) {
        throw new Error("rrweb returned an invalid recordings response.");
      }
      if (sshResult.status === "fulfilled" && !Array.isArray(sshResult.value)) {
        throw new Error("SecureAccess returned an invalid SSH recordings response.");
      }

      const webRecordings = webResult.status === "fulfilled"
        ? webResult.value.map((recording) => normalizeRecording(recording, "WEB"))
        : [];
      const sshRecordings = sshResult.status === "fulfilled"
        ? sshResult.value.map((recording) => normalizeRecording(recording, "SSH"))
        : [];
      setRecordings(
        [...webRecordings, ...sshRecordings].sort(compareRecordingsNewestFirst),
      );
      setCurrentPage(1);
    } catch (loadError) {
      console.error("Unable to load recordings:", loadError);
      setError("Unable to load recordings. Check the SecureAccess and rrweb connections, then refresh.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [applicationRole]);

  useEffect(() => {
    const initialTimer = setTimeout(() => {
      setNow(Date.now());
      void loadRecordings();
    }, 0);
    const clockTimer = setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      clearTimeout(initialTimer);
      clearInterval(clockTimer);
    };
  }, [loadRecordings]);

  const hasPendingFinalization = recordings.some(
    (recording) =>
      recording.recordingStatus === "stopped" &&
      !recording.recordingFinalized,
  );

  useEffect(() => {
    const refreshTimer = setInterval(
      () => void loadRecordings(true),
      hasPendingFinalization ? 3_000 : 30_000,
    );
    return () => clearInterval(refreshTimer);
  }, [hasPendingFinalization, loadRecordings]);

  const filteredRecordings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return recordings.filter((recording) => {
      const started = new Date(recording.startedAt || "").getTime();
      const from = getIstDayBoundary(fromDate);
      const toExclusive = getIstDayBoundary(toDate, true);
      const matchesQuery =
        !query ||
        [
          recording.displayId,
          recording.originalSessionId,
          recording.username,
          recording.target,
          recording.protocol,
          recording.firstPageUrl,
          recording.lastPageUrl,
          recording.lastFailure?.message,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(query));

      return (
        matchesQuery &&
        (protocolFilter === "ALL" || recording.protocol === protocolFilter) &&
        (!usernameFilter || recording.username === usernameFilter) &&
        (!targetFilter || recording.target === targetFilter) &&
        (!statusFilter || recording.recordingStatus === statusFilter) &&
        (!fromDate || (Number.isFinite(started) && started >= from)) &&
        (!toDate || (Number.isFinite(started) && started < toExclusive))
      );
    });
  }, [
    fromDate,
    protocolFilter,
    recordings,
    search,
    statusFilter,
    targetFilter,
    toDate,
    usernameFilter,
  ]);

  const usernames = useMemo(
    () => [...new Set(recordings.map((item) => item.username).filter(Boolean))].sort(),
    [recordings],
  );
  const targets = useMemo(
    () => [...new Set(recordings.map((item) => item.target).filter(Boolean))].sort(),
    [recordings],
  );
  const pageCount = Math.max(1, Math.ceil(filteredRecordings.length / PAGE_SIZE));
  const pageRecordings = filteredRecordings.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE,
  );
  function selectProtocol(protocol) {
    setCurrentPage(1);
    const next = new URLSearchParams(searchParams);
    if (protocol === "ALL") {
      next.delete("protocol");
    } else {
      next.set("protocol", protocol);
    }
    setSearchParams(next);
  }

  function updateFilter(setter, value) {
    setter(value);
    setCurrentPage(1);
  }

  function replayRecording(recording) {
    if (!recording.canReplay) {
      setError("This recording is not available for replay.");
      return;
    }
    void logSecureAccessEvent("recordings", "recording.replay.opened", {
      target: recording.target,
      sessionId: recording.originalSessionId,
      protocol: recording.protocol,
    });
    if (recording.protocol === "SSH") {
      if (!recording.playbackUrl) {
        setError("SecureAccess did not provide a valid recording playback route.");
        return;
      }
      window.location.assign(recording.playbackUrl);
      return;
    }
    const params = new URLSearchParams({
      sessionId: recording.originalSessionId,
    });
    navigate(`/admin/recordings/replay?${params.toString()}`);
  }

  function watchRecording(recording) {
    if (applicationRole !== "admin" || !recording.watchAvailable) {
      return;
    }
    const params = new URLSearchParams({
      protocol: recording.protocol,
      sessionId:
        recording.protocol === "SSH"
          ? recording.sessionId
          : recording.originalSessionId,
    });
    if (recording.protocol === "SSH") {
      params.set("recordingId", recording.originalSessionId);
    } else if (recording.warpgateSessionId) {
      params.set("warpgateSessionId", recording.warpgateSessionId);
    }
    navigate(`/admin/watch?${params.toString()}`);
  }

  return (
    <DashboardLayout>
      <div className="admin-page recording-replay-page">
        <div className="admin-page-header">
          <div>
            <h1>Recordings</h1>
            <p>Review and replay authorized SSH terminal and Web sessions.</p>
          </div>
          <button
            className="secondary-action-button"
            disabled={refreshing}
            onClick={() => void loadRecordings(true)}
            type="button"
          >
            <RefreshCw size={14} />
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        <div className="admin-stats-grid">
          <div className="admin-stat-card">
            <span>Total recordings</span>
            <strong>{recordings.length}</strong>
          </div>
          <div className="admin-stat-card">
            <span>Filtered recordings</span>
            <strong>{filteredRecordings.length}</strong>
          </div>
        </div>

        <div className="admin-table-card">
          <div className="admin-table-toolbar">
            <div>
              <h2>All recordings</h2>
              <p>Combined SecureAccess terminal and rrweb browser recordings.</p>
            </div>
            <div className="recordings-protocol-tabs" aria-label="Recording protocol">
              {["ALL", "SSH", "WEB"].map((protocol) => (
                <button
                  aria-pressed={protocolFilter === protocol}
                  className={protocolFilter === protocol ? "active" : ""}
                  key={protocol}
                  onClick={() => selectProtocol(protocol)}
                  type="button"
                >
                  {protocol === "ALL" ? "All" : protocol}
                </button>
              ))}
            </div>
          </div>

          <div className="recordings-filters">
            <input
              type="search"
              placeholder="Search ID, user, target or URL..."
              value={search}
              onChange={(event) => updateFilter(setSearch, event.target.value)}
            />
            <select
              value={usernameFilter}
              onChange={(event) => updateFilter(setUsernameFilter, event.target.value)}
            >
              <option value="">All users</option>
              {usernames.map((username) => (
                <option key={username} value={username}>{username}</option>
              ))}
            </select>
            <select
              value={targetFilter}
              onChange={(event) => updateFilter(setTargetFilter, event.target.value)}
            >
              <option value="">All targets</option>
              {targets.map((target) => (
                <option key={target} value={target}>{target}</option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(event) => updateFilter(setStatusFilter, event.target.value)}
            >
              <option value="">All statuses</option>
              <option value="recording">Recording</option>
              <option value="stopped">Stopped</option>
            </select>
            <label>
              From
              <input
                type="date"
                aria-label="From date"
                value={fromDate}
                onChange={(event) => updateFilter(setFromDate, event.target.value)}
              />
            </label>
            <label>
              To
              <input
                type="date"
                aria-label="To date"
                value={toDate}
                onChange={(event) => updateFilter(setToDate, event.target.value)}
              />
            </label>
          </div>

          {error && <div className="admin-page-state error">{error}</div>}
          {!error && Object.values(loadErrors).some(Boolean) && (
            <div className="admin-page-state error">
              {Object.values(loadErrors).filter(Boolean).join(" ")}
              {" Other recording types remain available below."}
            </div>
          )}
          {loading ? (
            <div className="admin-page-state">Loading recordings...</div>
          ) : error ? null : (
            pageRecordings.length === 0 ? (
              <div className="admin-page-state">No recordings found.</div>
            ) : (
              <div className="admin-table-wrapper">
                <table className="admin-table recordings-unified-table">
                  <thead>
                    <tr>
                      <th>Display identifier</th>
                      <th>User</th>
                      <th>Target</th>
                      <th>Protocol</th>
                      <th>Last activity (IST)</th>
                      <th>Status</th>
                      <th>Duration</th>
                      <th>Events</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <RecordingRows
                      canWatch={applicationRole === "admin"}
                      now={now}
                      onReplay={replayRecording}
                      onWatch={watchRecording}
                      recordings={pageRecordings}
                    />
                  </tbody>
                </table>
              </div>
            )
          )}

          {!loading && !error && (
            <div className="admin-panel-footer">
              <span>
                Showing {filteredRecordings.length === 0
                  ? 0
                  : (currentPage - 1) * PAGE_SIZE + 1}
                –{Math.min(currentPage * PAGE_SIZE, filteredRecordings.length)}
                {" of "}{filteredRecordings.length} recordings
              </span>
              <div className="sessions-pagination">
                <button
                  disabled={currentPage <= 1}
                  onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                  type="button"
                >
                  Previous
                </button>
                <span>Page {currentPage} of {pageCount}</span>
                <button
                  disabled={currentPage >= pageCount}
                  onClick={() => setCurrentPage((page) => Math.min(pageCount, page + 1))}
                  type="button"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
