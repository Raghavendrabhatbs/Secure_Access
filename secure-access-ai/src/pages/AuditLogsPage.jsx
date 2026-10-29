import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Search } from "lucide-react";

import { getSecureAccessAuditEvents } from "../api/audit";
import {
  getWarpgateLogs,
  normalizeWarpgateLogId,
  normalizeWarpgateLogTarget,
} from "../api/warpgate";
import { useAppRole } from "../auth/useAppRole";
import DashboardLayout from "../layouts/DashboardLayout";
import "../styles/AdminPages.css";

function formatTime(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function toSecureAccessRow(event) {
  const detailSummary = Object.entries(event.details || {})
    .map(([key, value]) => `${key}: ${String(value)}`)
    .join(" · ");

  return {
    id: `secure-access-${event.id}`,
    timestamp: event.timestamp,
    username: event.username,
    source: "SecureAccess",
    target: event.target,
    text: `${event.category} / ${event.action}${detailSummary ? ` — ${detailSummary}` : ""}`,
    session_id: event.session_id,
    category: event.category,
  };
}

function toWarpgateRow(event, index) {
  const eventId =
    normalizeWarpgateLogId(event.id) ||
    `${event.timestamp || "unknown"}-${index}`;
  return {
    ...event,
    id: `warpgate-${eventId}`,
    target: normalizeWarpgateLogTarget(event.target),
    session_id: normalizeWarpgateLogId(event.session_id),
    source: "SecureAccess Gateway",
    category: "SecureAccess Gateway",
  };
}

function AuditLogsPage() {
  const { role: applicationRole } = useAppRole();
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [errors, setErrors] = useState([]);

  const loadLogs = useCallback(async (background = false) => {
    setLoading(!background);
    setRefreshing(background);
    setErrors([]);

    const [warpgateResult, secureAccessResult] = await Promise.allSettled([
      getWarpgateLogs({ limit: 500, applicationRole }),
      getSecureAccessAuditEvents({ limit: 500 }),
    ]);

    const nextErrors = [];
    const combined = [];

    if (warpgateResult.status === "fulfilled") {
      if (!Array.isArray(warpgateResult.value)) {
        nextErrors.push("SecureAccess returned an invalid gateway log response.");
      } else {
        combined.push(...warpgateResult.value.map(toWarpgateRow));
      }
    } else {
      console.error("Failed loading SecureAccess gateway audit logs:", warpgateResult.reason);
      nextErrors.push(
        `SecureAccess gateway logs could not be loaded: ${
          warpgateResult.reason instanceof Error
            ? warpgateResult.reason.message
            : "Unknown error."
        }`,
      );
    }

    if (secureAccessResult.status === "fulfilled") {
      combined.push(...secureAccessResult.value.map(toSecureAccessRow));
    } else {
      console.error(
        "Failed loading SecureAccess audit events:",
        secureAccessResult.reason,
      );
      nextErrors.push(
        `SecureAccess events could not be loaded: ${
          secureAccessResult.reason instanceof Error
            ? secureAccessResult.reason.message
            : "Unknown error."
        }`,
      );
    }

    setLogs(
      combined.sort(
        (left, right) =>
          new Date(right.timestamp || 0).getTime() -
          new Date(left.timestamp || 0).getTime(),
      ),
    );
    setErrors(nextErrors);
    setLoading(false);
    setRefreshing(false);
  }, [applicationRole]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadLogs();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadLogs]);

  const filteredLogs = useMemo(() => {
    const query = search.trim().toLowerCase();
    return logs.filter((log) => {
      const sourceMatches =
        sourceFilter === "all" ||
        log.source.toLowerCase().replace(/\s+/g, "-") === sourceFilter;
      const searchMatches =
        !query || JSON.stringify(log).toLowerCase().includes(query);
      return sourceMatches && searchMatches;
    });
  }, [logs, search, sourceFilter]);

  const gatewayCount = logs.filter((log) => log.source === "SecureAccess Gateway").length;
  const secureAccessCount = logs.length - gatewayCount;

  return (
    <DashboardLayout>
      <div className="admin-page-header">
        <div>
          <h1>Audit Logs</h1>
          <p>Combined SecureAccess Gateway events and application activity.</p>
        </div>
        <button
          className="secondary-action-button"
          disabled={refreshing}
          onClick={() => void loadLogs(true)}
          type="button"
        >
          <RefreshCw size={14} />
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      <section className="admin-summary-grid">
        <div className="admin-summary-card">
          <span>Loaded Events</span>
          <strong>{logs.length}</strong>
        </div>
        <div className="admin-summary-card">
          <span>SecureAccess Gateway Events</span>
          <strong>{gatewayCount}</strong>
        </div>
        <div className="admin-summary-card">
          <span>SecureAccess Events</span>
          <strong>{secureAccessCount}</strong>
        </div>
        <div className="admin-summary-card">
          <span>Sources</span>
          <strong>2</strong>
        </div>
      </section>

      <section className="admin-panel">
        <div className="admin-panel-header">
          <div>
            <h2>Universal Activity Log</h2>
            <p>Events are ordered by time and labeled by their originating system.</p>
          </div>
        </div>

        <div className="admin-toolbar">
          <div className="admin-search">
            <Search size={15} />
            <input
              type="text"
              placeholder="Search logs..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          <select
            aria-label="Filter audit log source"
            className="admin-select"
            onChange={(event) => setSourceFilter(event.target.value)}
            value={sourceFilter}
          >
            <option value="all">All sources</option>
            <option value="secureaccess-gateway">SecureAccess Gateway</option>
            <option value="secureaccess">SecureAccess</option>
          </select>
        </div>

        {errors.map((message) => (
          <div className="admin-page-state error" key={message} role="alert">
            {message} {logs.length > 0 && "Other available events are still shown."}
          </div>
        ))}

        {loading ? (
          <div className="admin-page-state">Loading audit events...</div>
        ) : (
          <div className="admin-table-wrapper">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Source</th>
                  <th>Target</th>
                  <th>Event</th>
                  <th>Session</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="table-muted">{formatTime(log.timestamp)}</td>
                    <td>{log.username || "System"}</td>
                    <td>{log.source}</td>
                    <td>{log.target || "—"}</td>
                    <td>
                      <div className="table-primary">
                        {log.text || log.action || "Audit event"}
                      </div>
                    </td>
                    <td className="table-muted">{log.session_id || "—"}</td>
                  </tr>
                ))}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td
                      colSpan="6"
                      style={{
                        textAlign: "center",
                        height: "80px",
                        color: "#667085",
                      }}
                    >
                      {errors.length > 0
                        ? "Audit events could not be fully loaded."
                        : "No audit events found."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {!loading && (
          <div className="admin-panel-footer">
            <span>Showing {filteredLogs.length} of {logs.length} events</span>
            <button
              disabled={refreshing}
              onClick={() => void loadLogs(true)}
              type="button"
            >
              Refresh
            </button>
          </div>
        )}
      </section>
    </DashboardLayout>
  );
}

export default AuditLogsPage;
