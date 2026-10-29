import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Search,
  RefreshCw,
  Eye,
  Sparkles,
  OctagonX,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import DashboardLayout from "../layouts/DashboardLayout";
import { getAllWarpgateSessions, getWarpgateRecordings } from "../api/warpgate";
import { getRrwebRecordings } from "../api/recordings";
import {
  getLiveWarpgateSessions,
  terminateLiveWarpgateSession,
} from "../api/securitySessions";
import { logSecureAccessEvent } from "../api/audit";
import { useAppRole } from "../auth/useAppRole";
import { normalizeRecording } from "./recordings-model";

import "../styles/AdminPages.css";


function isToday(dateString) {
  if (!dateString) return false;

  const date = new Date(dateString);
  const today = new Date();

  return (
    date.getFullYear() === today.getFullYear() &&
    date.getMonth() === today.getMonth() &&
    date.getDate() === today.getDate()
  );
}


function formatDate(dateString) {
  if (!dateString) return "—";

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString();
}


function formatDuration(started, ended) {
  if (!started) return "—";

  const start = new Date(started);
  const end = ended
    ? new Date(ended)
    : new Date();

  const difference =
    Math.max(0, end.getTime() - start.getTime());

  const totalSeconds =
    Math.floor(difference / 1000);

  const hours =
    Math.floor(totalSeconds / 3600);

  const minutes =
    Math.floor(
      (totalSeconds % 3600) / 60
    );

  const seconds =
    totalSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }

  return `${seconds}s`;
}


function getProtocolClass(protocol) {
  const value =
    protocol
      ?.toString()
      .toUpperCase();

  if (value === "SSH") {
    return "type-badge ssh";
  }

  if (
    value === "HTTP" ||
    value === "HTTPS"
  ) {
    return "type-badge web";
  }

  return "type-badge access";
}


function SessionsPage() {
  const { role } = useAppRole();
  const navigate = useNavigate();
  const [sessions, setSessions] =
    useState([]);
  const [activeSessionIds, setActiveSessionIds] =
    useState(() => new Set());
  const [watchableRecordings, setWatchableRecordings] = useState({
    ssh: [],
    web: [],
  });

  const [search, setSearch] =
    useState("");

  const [protocolFilter, setProtocolFilter] =
    useState("ALL");

  const [activeTab, setActiveTab] =
    useState("live");

  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 50;

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");
  const [watchError, setWatchError] =
    useState("");
  const [historyWarning, setHistoryWarning] =
    useState("");
  const [terminationCandidate, setTerminationCandidate] =
    useState(null);
  const [terminationPending, setTerminationPending] =
    useState(false);
  const [terminationMessage, setTerminationMessage] =
    useState(null);


  const loadSessions = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [activeResult, sessionResult, webResult, sshResult] = await Promise.allSettled([
        getLiveWarpgateSessions(),
        getAllWarpgateSessions(role),
        getRrwebRecordings(),
        getWarpgateRecordings({ applicationRole: role }),
      ]);
      if (activeResult.status === "rejected") {
        throw activeResult.reason;
      }
      const activeItems = activeResult.value.filter(
        (session) => session?.id && session.ended === null,
      );
      setActiveSessionIds(new Set(activeItems.map((session) => session.id)));

      const data = sessionResult.status === "fulfilled"
        ? sessionResult.value
        : [];
      const items = Array.isArray(data)
        ? data
        : Array.isArray(data?.items)
          ? data.items
          : [];
      const completedItems = items.filter((session) => session?.ended != null);

      setSessions([...activeItems, ...completedItems]);
      setHistoryWarning(
        sessionResult.status === "rejected"
          ? "Completed session history could not be loaded. The live list is from Warpgate."
          : "",
      );
      setCurrentPage(1);
      const web = webResult.status === "fulfilled"
        ? webResult.value.map((recording) => normalizeRecording(recording, "WEB"))
        : [];
      const ssh = sshResult.status === "fulfilled"
        ? sshResult.value.map((recording) => normalizeRecording(recording, "SSH"))
        : [];
      setWatchableRecordings({ web, ssh });
      setWatchError(
        webResult.status === "rejected" || sshResult.status === "rejected"
          ? "Live Watch availability could not be verified for every recording source."
          : "",
      );
      if (sessionResult.status === "rejected") {
        console.error("Unable to load completed Warpgate sessions:", sessionResult.reason);
      }
      if (webResult.status === "rejected") {
        console.error("Unable to verify active web recordings:", webResult.reason);
      }
      if (sshResult.status === "rejected") {
        console.error("Unable to verify active SSH recordings:", sshResult.reason);
      }

    } catch (err) {
      console.error(
        "Failed loading sessions:",
        err
      );

      setError(
        err instanceof Error
          ? `Unable to load sessions: ${err.message}`
          : "Unable to load sessions from SecureAccess.",
      );
      setActiveSessionIds(new Set());

    } finally {
      setLoading(false);
    }
  }, [role]);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadSessions();
    }, 0);
    const refreshId = window.setInterval(() => void loadSessions(), 15_000);
    return () => {
      window.clearTimeout(timeoutId);
      window.clearInterval(refreshId);
    };
  }, [loadSessions]);

  function watchSession(session) {
    const recording = findWatchableRecording(session);
    if (role !== "admin" || session.ended !== null || !recording) return;
    const protocol = session.protocol?.toUpperCase();
    const params = new URLSearchParams({
      protocol: recording.protocol,
      sessionId: protocol === "SSH" ? session.id : recording.originalSessionId,
    });
    if (protocol === "SSH") {
      params.set("recordingId", recording.originalSessionId);
    } else {
      params.set("warpgateSessionId", session.id);
    }
    navigate(`/admin/watch?${params.toString()}`);
  }

  function findWatchableRecording(session) {
    const protocol = session.protocol?.toUpperCase();
    return protocol === "SSH"
      ? watchableRecordings.ssh.find(
          (item) =>
            item.watchAvailable &&
            item.sessionId === session.id,
        )
      : ["HTTP", "HTTPS"].includes(protocol)
        ? watchableRecordings.web.find(
            (item) =>
              item.watchAvailable &&
              item.warpgateSessionId === session.id,
          )
        : null;
  }


  /*
   * LIVE:
   * Warpgate returns ended: null
   */
  const liveSessions =
    useMemo(() => {
      return sessions.filter(
        (session) =>
          activeSessionIds.has(session.id)
      );
    }, [sessions, activeSessionIds]);


  /*
   * COMPLETED:
   * Warpgate returns an ended timestamp
   */
  const completedSessions =
    useMemo(() => {
      return sessions.filter(
        (session) =>
          session.ended !== null
      );
    }, [sessions]);


  const sessionsToday =
    useMemo(() => {
      return sessions.filter(
        (session) =>
          isToday(session.started)
      ).length;
    }, [sessions]);


  const sshToday =
    useMemo(() => {
      return sessions.filter(
        (session) => {

          return (
            isToday(session.started) &&
            session.protocol
              ?.toUpperCase() === "SSH"
          );

        }
      ).length;
    }, [sessions]);


  const webToday =
    useMemo(() => {
      return sessions.filter(
        (session) => {

          if (!isToday(session.started)) {
            return false;
          }

          const protocol =
            session.protocol
              ?.toUpperCase();

          return (
            protocol === "HTTP" ||
            protocol === "HTTPS"
          );

        }
      ).length;
    }, [sessions]);


  /*
   * FIRST choose Live/Completed.
   * THEN apply search/protocol filters.
   */
  const displayedSessions =
    useMemo(() => {

      let result =
        activeTab === "live"
          ? [...liveSessions]
          : [...completedSessions];


      if (protocolFilter !== "ALL") {

        result = result.filter(
          (session) => {

            const protocol =
              session.protocol
                ?.toUpperCase();

            if (protocolFilter === "WEB") {

              return (
                protocol === "HTTP" ||
                protocol === "HTTPS"
              );

            }

            return (
              protocol ===
              protocolFilter
            );

          }
        );

      }


      const query =
        search
          .trim()
          .toLowerCase();


      if (query) {

        result = result.filter(
          (session) => {

            const searchableText =
              [
                session.id,
                session.username,
                session.target,
                session.protocol,
                session.node_hostname,
                session.node_id,
                session.ticket_id,
              ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();

            return searchableText.includes(
              query
            );

          }
        );

      }


      return result;

    }, [
      activeTab,
      liveSessions,
      completedSessions,
      protocolFilter,
      search,
    ]);

  const pageCount = Math.max(
    1,
    Math.ceil(displayedSessions.length / pageSize),
  );
  const pageSessions = displayedSessions.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize,
  );

  function switchTab(tab) {
    setActiveTab(tab);
    setCurrentPage(1);

    /*
     * Reset filters when switching between
     * Live and Completed.
     */
    setSearch("");
    setProtocolFilter("ALL");
  }

  async function confirmTermination() {
    if (!terminationCandidate || terminationPending) return;
    const selected = terminationCandidate;
    setTerminationPending(true);
    setTerminationMessage(null);
    try {
      const result = await terminateLiveWarpgateSession(
        selected.id,
        "Manually terminated by an administrator.",
      );
      void logSecureAccessEvent("security", "warpgate.session.termination", {
        sessionId: selected.id,
        username: selected.username || null,
        target: selected.target || null,
        result: result.status,
      });
      setTerminationMessage({
        type: result.status === "confirmed" || result.status === "already_ended"
          ? "success"
          : "warning",
        text: result.status === "confirmed"
          ? "Warpgate confirmed that the session ended."
          : result.status === "already_ended"
            ? "The session had already ended."
            : "Warpgate did not confirm termination. Refresh and verify the session state.",
      });
      setTerminationCandidate(null);
      await loadSessions();
    } catch (error) {
      console.error("Unable to terminate the Warpgate session:", error);
      setTerminationMessage({
        type: "error",
        text: error instanceof Error
          ? error.message
          : "Unable to terminate the selected session.",
      });
    } finally {
      setTerminationPending(false);
    }
  }


  return (
    <DashboardLayout>

      <div className="admin-page-header">

        <div>

          <h1>
            Sessions
          </h1>

          <p>
            Monitor live privileged sessions and review completed activity.
          </p>

        </div>


        <button
          className="secondary-action-button"
          onClick={loadSessions}
        >

          <RefreshCw size={14} />

          Refresh

        </button>

      </div>


      <section className="admin-summary-grid">

        <div className="admin-summary-card">

          <span>
            Live Sessions
          </span>

          <strong>
            {loading
              ? "—"
              : liveSessions.length}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            Sessions Today
          </span>

          <strong>
            {loading
              ? "—"
              : sessionsToday}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            SSH Today
          </span>

          <strong>
            {loading
              ? "—"
              : sshToday}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            Web Today
          </span>

          <strong>
            {loading
              ? "—"
              : webToday}
          </strong>

        </div>

      </section>


      <section className="admin-panel">

        <div className="admin-panel-header">

          <div>

            <h2>
              Session Monitoring
            </h2>

            <p>
              Real SecureAccess session data.
            </p>

          </div>


          <div className="session-tabs">

            <button
              type="button"
              className={
                activeTab === "live"
                  ? "session-tab active"
                  : "session-tab"
              }
              onClick={() =>
                switchTab("live")
              }
            >

              Live

              <span>
                {liveSessions.length}
              </span>

            </button>


            <button
              type="button"
              className={
                activeTab === "completed"
                  ? "session-tab active"
                  : "session-tab"
              }
              onClick={() =>
                switchTab("completed")
              }
            >

              Completed

              <span>
                {completedSessions.length}
              </span>

            </button>

          </div>

        </div>


        <div className="admin-toolbar">

          <div className="admin-search">

            <Search size={15} />

            <input
              type="text"
              placeholder={
                activeTab === "live"
                  ? "Search live sessions..."
                  : "Search completed sessions..."
              }
              value={search}
              onChange={(event) =>
                {
                  setSearch(event.target.value);
                  setCurrentPage(1);
                }
              }
            />

          </div>


          <select
            value={protocolFilter}
            onChange={(event) =>
              {
                setProtocolFilter(event.target.value);
                setCurrentPage(1);
              }
            }
          >

            <option value="ALL">
              All protocols
            </option>

            <option value="SSH">
              SSH
            </option>

            <option value="WEB">
              Web
            </option>

          </select>

        </div>


        {loading && (

          <div
            style={{
              padding: "35px",
              textAlign: "center",
              color: "#667085",
            }}
          >
            Loading sessions...
          </div>

        )}


        {!loading && error && (

          <div
            style={{
              padding: "35px",
              textAlign: "center",
              color: "#b42318",
            }}
          >
            {error}
          </div>

        )}


        {!loading &&
          !error && (

          <div className="admin-table-wrapper">

              {historyWarning && (
                <div className="admin-page-state error" role="status">
                  {historyWarning}
                </div>
              )}
              {terminationMessage && (
                <div className={`admin-page-state ${terminationMessage.type}`} role="status">
                  {terminationMessage.text}
                </div>
              )}
              {watchError && (
              <div className="admin-page-state error" role="status">
                {watchError} Session and recording access remain unchanged.
              </div>
            )}

            <table className="admin-table">

              <thead>

                <tr>
                  <th>Session</th>
                  <th>User</th>
                  <th>Target</th>
                  <th>Protocol</th>
                  <th>Started</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>

              </thead>


              <tbody>

                {pageSessions.map(
                  (session) => {

                    const isLive = activeSessionIds.has(session.id);

                    return (

                      <tr key={session.id}>

                        <td
                          className="table-primary"
                          title={session.id}
                        >

                          {session.id
                            ?.slice(0, 8)}
                          ...

                        </td>


                        <td>

                          {session.username ||
                            "—"}

                        </td>


                        <td>

                          {session.target ||
                            "—"}

                        </td>


                        <td>

                          <span
                            className={
                              getProtocolClass(
                                session.protocol
                              )
                            }
                          >

                            {session.protocol ||
                              "—"}

                          </span>

                        </td>


                        <td className="table-muted">

                          {formatDate(
                            session.started
                          )}

                        </td>


                        <td className="table-muted">

                          {formatDuration(
                            session.started,
                            session.ended
                          )}

                        </td>


                        <td>

                          <span
                            className={
                              isLive
                                ? "status-badge active"
                                : "status-badge completed"
                            }
                          >

                            {isLive
                              ? "Live"
                              : "Completed"}

                          </span>

                        </td>


                        <td>
                          <div className="session-row-actions">
                            <button
                              type="button"
                              className="secondary-action-button"
                              aria-label={`Ask AI about session ${session.id}`}
                              title="Ask AI about this session"
                              onClick={() => navigate(`/admin/ai-assistant?session_id=${encodeURIComponent(session.id)}`)}
                            >
                              <Sparkles size={13} />
                              Ask AI
                            </button>
                            {isLive &&
                            role === "admin" &&
                            findWatchableRecording(session) ? (
                              <button
                                type="button"
                                className="secondary-action-button"
                                onClick={() => watchSession(session)}
                              >
                                <Eye size={13} />
                                Watch
                              </button>
                            ) : null}
                            {isLive && role === "admin" ? (
                              <button
                                type="button"
                                className="secondary-action-button session-terminate-button"
                                aria-label={`Terminate session ${session.id}`}
                                onClick={() => {
                                  setTerminationMessage(null);
                                  setTerminationCandidate(session);
                                }}
                              >
                                <OctagonX size={13} />
                                Terminate
                              </button>
                            ) : null}
                          </div>
                        </td>

                      </tr>

                    );
                  }
                )}


                {displayedSessions.length ===
                  0 && (

                  <tr>

                    <td
                      colSpan="8"
                      style={{
                        height: "90px",
                        textAlign: "center",
                        color: "#667085",
                      }}
                    >

                      {activeTab === "live"
                        ? "No live sessions."
                        : "No completed sessions."}

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        )}


        {!loading &&
          !error && (

          <div className="admin-panel-footer">

            <span>
              Showing{" "}
              {displayedSessions.length === 0
                ? 0
                : (currentPage - 1) * pageSize + 1}
              {"–"}
              {Math.min(currentPage * pageSize, displayedSessions.length)}
              {" of "}
              {displayedSessions.length}
              {activeTab === "live" ? " live sessions" : " completed sessions"}
            </span>


            <div className="sessions-pagination">
              <button type="button" onClick={loadSessions}>Refresh</button>
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                disabled={currentPage <= 1}
              >
                Previous
              </button>
              <span>Page {currentPage} of {pageCount}</span>
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.min(pageCount, page + 1))}
                disabled={currentPage >= pageCount}
              >
                Next
              </button>
            </div>

          </div>

        )}

      </section>

      {terminationCandidate && (
        <div
          className="session-termination-backdrop"
          onMouseDown={(event) => {
            if (
              event.target === event.currentTarget &&
              !terminationPending
            ) {
              setTerminationCandidate(null);
            }
          }}
        >
          <section
            aria-labelledby="session-termination-title"
            aria-modal="true"
            className="session-termination-dialog"
            role="dialog"
          >
            <h2 id="session-termination-title">Terminate active session?</h2>
            <p>
              This will disconnect the active Warpgate session. This action
              cannot be undone.
            </p>
            <dl>
              <div><dt>User</dt><dd>{terminationCandidate.username || "Unknown"}</dd></div>
              <div><dt>Target</dt><dd>{terminationCandidate.target || "Unknown"}</dd></div>
              <div><dt>Protocol</dt><dd>{terminationCandidate.protocol}</dd></div>
              <div><dt>Session ID</dt><dd>{terminationCandidate.id}</dd></div>
              <div><dt>Started</dt><dd>{formatDate(terminationCandidate.started)}</dd></div>
            </dl>
            <div className="session-termination-actions">
              <button
                type="button"
                className="secondary-action-button"
                disabled={terminationPending}
                onClick={() => setTerminationCandidate(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="danger-action-button"
                disabled={terminationPending}
                onClick={() => void confirmTermination()}
              >
                {terminationPending ? "Terminating..." : "Confirm termination"}
              </button>
            </div>
          </section>
        </div>
      )}

    </DashboardLayout>
  );
}


export default SessionsPage;