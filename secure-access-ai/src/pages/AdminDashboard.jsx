import {
  AlertTriangle,
  ArrowRight,
  CircleAlert,
  Eye,
  RefreshCw,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  canReplayRecording,
  getRrwebRecordings,
} from "../api/recordings";
import {
  getAllWarpgateSessions,
  getWarpgateLogs,
  getWarpgateTargets,
  getWarpgateUsers,
} from "../api/warpgate";
import DashboardLayout from "../layouts/DashboardLayout";

import "../styles/AdminDashboard.css";

const EMPTY_ERRORS = {
  users: "",
  targets: "",
  sessions: "",
  recordings: "",
  logs: "",
};

function asArray(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (Array.isArray(value?.items)) {
    return value.items;
  }
  return [];
}

function getSessionProtocol(session) {
  return session.protocol?.toString().toUpperCase() || "UNKNOWN";
}

function getTargetProtocol(target) {
  const kind = target.options?.kind?.toString().toLowerCase();
  if (kind === "ssh") return "SSH";
  if (kind === "http") return "WEB";
  if (kind === "mysql") return "MYSQL";
  if (kind === "postgres" || kind === "postgresql") return "POSTGRES";
  if (kind === "kubernetes") return "KUBERNETES";
  if (kind === "rdp") return "RDP";
  if (kind === "vnc") return "VNC";
  return "UNKNOWN";
}

function formatDuration(started, now) {
  if (!now) {
    return "—";
  }
  const start = new Date(started || "").getTime();
  if (!Number.isFinite(start)) {
    return "—";
  }
  const seconds = Math.max(0, Math.floor((now - start) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return "<1m";
}

function normalizeStatus(status) {
  switch (status) {
    case "recording":
      return "Recording";
    case "starting":
      return "Starting";
    case "failed":
      return "Failed";
    case "stopped":
      return "Stopped";
    default:
      return "Unknown";
  }
}

function findRecordingForSession(session, recordings) {
  const protocol = getSessionProtocol(session);
  if (protocol !== "HTTP" && protocol !== "HTTPS") {
    return null;
  }

  const username = session.username?.toLowerCase();
  const target = session.target?.toLowerCase();
  const sessionStarted = new Date(session.started || "").getTime();
  if (!username || !target || !Number.isFinite(sessionStarted)) {
    return null;
  }

  const candidates = recordings
    .filter((recording) => {
      if (
        recording.username?.toLowerCase() !== username ||
        recording.target?.toLowerCase() !== target
      ) {
        return false;
      }
      const recordingStarted = new Date(recording.startedAt || "").getTime();
      return (
        Number.isFinite(recordingStarted) &&
        Math.abs(recordingStarted - sessionStarted) <= 10 * 60 * 1000
      );
    })
    .sort(
      (left, right) =>
        new Date(right.startedAt || 0).getTime() -
        new Date(left.startedAt || 0).getTime(),
    );

  return candidates.length === 1 ? candidates[0] : null;
}

function getLogText(log) {
  return log.text || log.message || log.event || "Gateway audit event";
}

function isSecurityFailure(log) {
  return /denied|failed|unauthori[sz]ed|invalid credential|authentication error/i.test(
    getLogText(log),
  );
}

function AdminDashboard() {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [targets, setTargets] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [recordings, setRecordings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [errors, setErrors] = useState(EMPTY_ERRORS);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [now, setNow] = useState(0);

  const loadDashboard = useCallback(async (isRefresh = false) => {
    if (isRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    const requests = await Promise.allSettled([
      getWarpgateUsers(),
      getWarpgateTargets(),
      getAllWarpgateSessions("admin"),
      getRrwebRecordings(),
      getWarpgateLogs({ limit: 100 }),
    ]);
    const [userResult, targetResult, sessionResult, recordingResult, logResult] =
      requests;
    const nextErrors = { ...EMPTY_ERRORS };

    if (userResult.status === "fulfilled") {
      setUsers(asArray(userResult.value));
    } else {
      console.error("Unable to load dashboard users:", userResult.reason);
      nextErrors.users = "Unable to load users from SecureAccess.";
    }

    if (targetResult.status === "fulfilled") {
      setTargets(asArray(targetResult.value));
    } else {
      console.error("Unable to load dashboard targets:", targetResult.reason);
      nextErrors.targets = "Unable to load targets from SecureAccess.";
    }

    if (sessionResult.status === "fulfilled") {
      setSessions(asArray(sessionResult.value));
    } else {
      console.error("Unable to load dashboard sessions:", sessionResult.reason);
      nextErrors.sessions = "Unable to load sessions from SecureAccess.";
    }

    if (recordingResult.status === "fulfilled") {
      setRecordings(asArray(recordingResult.value));
    } else {
      console.error("Unable to load rrweb recordings:", recordingResult.reason);
      nextErrors.recordings = "Unable to load recording status from rrweb.";
    }

    if (logResult.status === "fulfilled") {
      setLogs(asArray(logResult.value));
    } else {
      console.error("Unable to load SecureAccess gateway audit logs:", logResult.reason);
      nextErrors.logs = "Unable to load audit activity from SecureAccess.";
    }

    setErrors(nextErrors);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    const initialTimer = setTimeout(() => {
      setNow(Date.now());
      void loadDashboard();
    }, 0);
    const refreshTimer = setInterval(() => {
      void loadDashboard(true);
    }, 30_000);
    const clockTimer = setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      clearTimeout(initialTimer);
      clearInterval(refreshTimer);
      clearInterval(clockTimer);
    };
  }, [loadDashboard]);

  const liveSessions = useMemo(
    () => sessions.filter((session) => !session.ended),
    [sessions],
  );
  const sessionsToday = useMemo(() => {
    const today = new Date(now);
    return sessions.filter((session) => {
      const started = new Date(session.started || "");
      return (
        !Number.isNaN(started.getTime()) &&
        started.getFullYear() === today.getFullYear() &&
        started.getMonth() === today.getMonth() &&
        started.getDate() === today.getDate()
      );
    });
  }, [now, sessions]);

  const usersInSession = new Set(
    liveSessions.map((session) => session.username).filter(Boolean),
  ).size;
  const idleUsers = Math.max(0, users.length - usersInSession);
  const liveSSH = liveSessions.filter(
    (session) => getSessionProtocol(session) === "SSH",
  ).length;
  const liveWeb = liveSessions.filter((session) =>
    ["HTTP", "HTTPS"].includes(getSessionProtocol(session)),
  ).length;
  const todaySSH = sessionsToday.filter(
    (session) => getSessionProtocol(session) === "SSH",
  ).length;
  const todayWeb = sessionsToday.filter((session) =>
    ["HTTP", "HTTPS"].includes(getSessionProtocol(session)),
  ).length;
  const sshTargets = targets.filter(
    (target) => getTargetProtocol(target) === "SSH",
  ).length;
  const webTargets = targets.filter(
    (target) => getTargetProtocol(target) === "WEB",
  ).length;

  const attentionItems = [
    ...recordings
      .filter(
        (recording) =>
          recording.recordingStatus === "failed" &&
          !recording.lastFailure?.resolvedAt,
      )
      .map((recording) => ({
        key: `recording-${recording.sessionId}`,
        title: "Recording failure",
        detail:
          recording.lastFailure?.message ||
          `${recording.username || "Unknown user"} · ${recording.target || "Unknown target"}`,
        icon: CircleAlert,
        onClick: () => navigate("/admin/recordings"),
      })),
    ...logs
      .filter(isSecurityFailure)
      .slice(0, 5)
      .map((log, index) => ({
        key: `audit-${log.id || log.timestamp || index}`,
        title: "Security or access event",
        detail: getLogText(log),
        icon: AlertTriangle,
        onClick: () => navigate("/admin/audit-logs"),
      })),
  ].slice(0, 5);

  const dashboardLiveSessions = liveSessions.slice(0, 4);
  const loadErrors = Object.values(errors).filter(Boolean);

  return (
    <DashboardLayout>
      <div className="dashboard-header">
        <div>
          <h1>Dashboard</h1>
          <p>Security, access and recording overview.</p>
        </div>
        <div className="dashboard-actions">
          <button
            className="secondary-action-button"
            onClick={() => void loadDashboard(true)}
            disabled={refreshing}
          >
            <RefreshCw size={14} />
            {refreshing ? "Refreshing..." : "Refresh"}
          </button>
          <button
            className="connect-button"
            onClick={() => navigate("/admin/targets")}
          >
            <span>＋</span>
            Connect to Target
          </button>
        </div>
      </div>

      {loadErrors.length > 0 && (
        <div className="dashboard-error" role="status">
          {loadErrors.join(" ")}
        </div>
      )}

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-title">Active Sessions</div>
          <div className="stat-value">
            {loading || errors.sessions ? "—" : liveSessions.length}
          </div>
          <div className="stat-subtext">
            {errors.sessions ? "Session data unavailable" : <>{liveSSH} SSH <span>•</span> {liveWeb} Web</>}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Sessions Today</div>
          <div className="stat-value">
            {loading || errors.sessions ? "—" : sessionsToday.length}
          </div>
          <div className="stat-subtext">
            {errors.sessions ? "Session data unavailable" : <>{todaySSH} SSH <span>•</span> {todayWeb} Web</>}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Users</div>
          <div className="stat-value">
            {loading || errors.users ? "—" : users.length}
          </div>
          <div className="stat-subtext status-subtext">
            {errors.users || errors.sessions ? (
              "User activity unavailable"
            ) : (
              <>
                <span className="dot green" /> {usersInSession} In Session
                <span className="separator">•</span>
                <span className="dot gray" /> {idleUsers} Idle
              </>
            )}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-title">Targets</div>
          <div className="stat-value">
            {loading || errors.targets ? "—" : targets.length}
          </div>
          <div className="stat-subtext">
            {errors.targets ? "Target data unavailable" : <>{sshTargets} SSH <span>•</span> {webTargets} Web</>}
          </div>
        </div>
      </section>

      <section className="dashboard-main-grid">
        <div className="panel live-panel">
          <div className="panel-header">
            <div>
              <h2>Live Sessions</h2>
              <p>Privileged sessions currently in progress.</p>
            </div>
            <button
              className="panel-link"
              onClick={() => navigate("/admin/sessions")}
            >
              View all <ArrowRight size={14} />
            </button>
          </div>
          <div className="live-table-wrapper">
            <table className="live-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Target</th>
                  <th>Protocol</th>
                  <th>Duration</th>
                  <th>Recording</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan="6" className="dashboard-table-state">Loading sessions...</td></tr>
                )}
                {!loading && errors.sessions && (
                  <tr><td colSpan="6" className="dashboard-table-state">{errors.sessions}</td></tr>
                )}
                {!loading && !errors.sessions && dashboardLiveSessions.map((session) => {
                  const protocol = getSessionProtocol(session);
                  const isWeb = ["HTTP", "HTTPS"].includes(protocol);
                  const recording = isWeb && !errors.recordings
                    ? findRecordingForSession(session, recordings)
                    : null;
                  const sessionId = recording?.sessionId ||
                    recording?.file?.replace(/\.json$/, "");
                  const canReplay = Boolean(
                    recording &&
                      canReplayRecording(recording) &&
                      sessionId,
                  );
                  return (
                    <tr key={session.id}>
                      <td className="user-cell">{session.username || "—"}</td>
                      <td>{session.target || "—"}</td>
                      <td>
                        <span className={`protocol ${protocol === "SSH" ? "ssh" : "web"}`}>
                          {isWeb ? "WEB" : protocol}
                        </span>
                      </td>
                      <td>{formatDuration(session.started, now)}</td>
                      <td>
                        {errors.recordings
                          ? "Unavailable"
                          : isWeb
                            ? normalizeStatus(recording?.recordingStatus)
                            : "Not applicable"}
                      </td>
                      <td className="action-cell">
                        <button
                          className="watch-button"
                          disabled={!canReplay}
                          title={canReplay ? "Replay recording" : "No linked replay is available"}
                          onClick={() => navigate(`/admin/recordings/replay?sessionId=${encodeURIComponent(sessionId)}`)}
                        >
                          <Eye size={14} /> Watch
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {!loading && !errors.sessions && dashboardLiveSessions.length === 0 && (
                  <tr><td colSpan="6" className="dashboard-table-state">No live sessions.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel attention-panel">
          <div className="panel-header">
            <div>
              <h2>Attention Required</h2>
              <p>Failures and security events from connected services.</p>
            </div>
          </div>
          <div className="attention-list">
            {(errors.recordings || errors.logs) && attentionItems.length === 0 && (
              <div className="dashboard-table-state">
                {errors.recordings || errors.logs}
              </div>
            )}
            {!errors.recordings && !errors.logs && attentionItems.length === 0 && (
              <div className="dashboard-table-state">No unresolved recording failures or security events.</div>
            )}
            {attentionItems.map((item) => {
              const Icon = item.icon;
              return (
                <button className="attention-row" key={item.key} onClick={item.onClick}>
                  <div className="attention-icon warning"><Icon size={17} /></div>
                  <div className="attention-text">
                    <strong>{item.title}</strong>
                    <span>{item.detail}</span>
                  </div>
                  <ArrowRight size={16} />
                </button>
              );
            })}
          </div>
        </div>
      </section>

    </DashboardLayout>
  );
}

export default AdminDashboard;
