import { useCallback, useEffect, useMemo, useState } from "react";
import {
  BookOpen,
  ChevronDown,
  Copy,
  RefreshCw,
  Search,
  Terminal,
  X,
} from "lucide-react";
import {
  createWarpgateWebSshSession,
  deleteWarpgateWebSshSession,
  getAccessibleWarpgateTargets,
  getWarpgateInfo,
} from "../api/warpgate";
import { logSecureAccessEvent } from "../api/audit";
import DashboardLayout from "../layouts/DashboardLayout";
import { useAppRole } from "../auth/useAppRole";
import { createSshInstructionCommands } from "./ssh-instructions";

import "../styles/AdminPages.css";

async function fetchSshTargets() {
  const data = await getAccessibleWarpgateTargets();
  const items = Array.isArray(data)
    ? data
    : data?.items || data?.targets || [];

  return items.filter((target) => {
    const kind = (target?.kind || target?.options?.kind)
      ?.toString()
      .toLowerCase();

    return kind === "ssh";
  });
}

function AccessInstructionsDialog({ target, info, onClose }) {
  const [advanced, setAdvanced] = useState(false);
  const [copyError, setCopyError] = useState("");
  const username = info?.username || "";
  const gatewayHost =
    info?.external_hosts?.ssh ||
    info?.external_host ||
    window.location.hostname;
  const commands = (() => {
    try {
      return createSshInstructionCommands({
        username,
        targetName: target.name,
        gatewayHost,
        port: info?.ports?.ssh,
      });
    } catch {
      return null;
    }
  })();

  async function copy(value) {
    try {
      await navigator.clipboard.writeText(value);
      setCopyError("");
    } catch (error) {
      console.error("Unable to copy the SSH access instruction:", error);
      setCopyError("Clipboard access failed. Select and copy the command manually.");
    }
  }

  function commandField(label, value) {
    return (
      <div className="ssh-instruction-field">
        <label>{label}</label>
        <div>
          <code>{value || "Unavailable"}</code>
          {value && (
            <button
              type="button"
              aria-label={`Copy ${label.toLowerCase()}`}
              onClick={() => void copy(value)}
            >
              <Copy size={15} />
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      className="ssh-instructions-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        aria-labelledby="ssh-instructions-title"
        aria-modal="true"
        className="ssh-instructions-dialog"
        role="dialog"
      >
        <header>
          <h2 id="ssh-instructions-title">Access instructions</h2>
          <button type="button" aria-label="Close" onClick={onClose}>
            <X size={18} />
          </button>
        </header>
        <div className="ssh-instructions-content">
          <label className="ssh-instruction-user">
            Select a user
            <input readOnly value={username || "Unavailable"} />
          </label>
          {commandField("Example SSH command", commands?.ssh)}
          <button
            aria-expanded={advanced}
            className="ssh-instructions-advanced-toggle"
            onClick={() => setAdvanced((value) => !value)}
            type="button"
          >
            <ChevronDown size={17} className={advanced ? "expanded" : ""} />
            Advanced
          </button>
          {advanced && (
            <div className="ssh-instructions-advanced">
              {commandField("Example SCP command", commands?.scp)}
              {commandField("SecureAccess SSH endpoint", commands?.endpoint)}
            </div>
          )}
          {copyError && (
            <p className="ssh-instruction-copy-error" role="alert">
              {copyError}
            </p>
          )}
          {!commands && (
            <p className="ssh-instruction-copy-error" role="alert">
              SSH endpoint information is unavailable. Refresh the page or contact your administrator.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}

export default function SSHAccessPage() {
  const { role } = useAppRole();
  const [targets, setTargets] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [connectionError, setConnectionError] = useState("");
  const [connectingTargetId, setConnectingTargetId] = useState("");
  const [accessInstructionsTarget, setAccessInstructionsTarget] = useState(null);
  const [warpgateInfo, setWarpgateInfo] = useState(null);

  useEffect(() => {
    let active = true;

    getWarpgateInfo()
      .then((info) => {
        if (active) setWarpgateInfo(info);
      })
      .catch((infoError) => {
        console.error("Failed to load SSH access instruction details:", infoError);
      });

    fetchSshTargets()
      .then((sshTargets) => {
        if (active) {
          setTargets(sshTargets);
        }
      })
      .catch((err) => {
        console.error("Failed to load SSH targets:", err);
        if (active) {
          setError(err.message || "Failed to load SSH targets.");
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  const loadTargets = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      setTargets(await fetchSshTargets());
    } catch (err) {
      console.error("Failed to load SSH targets:", err);
      setError(err.message || "Failed to load SSH targets.");
    } finally {
      setLoading(false);
    }
  }, []);

  const filteredTargets = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) {
      return targets;
    }

    return targets.filter((target) => {
      const name = target?.name?.toLowerCase() || "";
      const description =
        target?.description?.toLowerCase() || "";
      const host = target?.options?.host?.toLowerCase() || "";

      return (
        name.includes(query) ||
        description.includes(query) ||
        host.includes(query)
      );
    });
  }, [targets, search]);

  function getAddress(target) {
    const options = target?.options;

    if (!options) {
      return "—";
    }

    if (options.host) {
      return options.port
        ? `${options.host}:${options.port}`
        : options.host;
    }

    return "—";
  }

  function getAccessRole(target) {
    const roles = target?.allow_roles;

    if (!Array.isArray(roles) || roles.length === 0) {
      return "All authorized users";
    }

    return roles.join(", ");
  }

  async function handleConnect(target) {
    if (role !== "admin" && role !== "developer") {
      setConnectionError("Your role is not permitted to open SSH sessions.");
      return;
    }
    if (!target?.id || connectingTargetId) return;

    const terminalWindow = window.open("about:blank", "_blank");
    if (!terminalWindow) {
      setConnectionError(
        "The SSH terminal was blocked by your browser. Allow pop-ups for SecureAccess and try again.",
      );
      return;
    }

    setConnectionError("");
    setConnectingTargetId(target.id);
    let sessionId = null;
    try {
      terminalWindow.document.title = "Connecting to SSH target";
      terminalWindow.document.body.textContent =
        "Starting your secure SSH session…";
      sessionId = await createWarpgateWebSshSession(target.id);
      if (terminalWindow.closed) {
        throw new Error(
          "The SSH terminal window was closed before the session could open.",
        );
      }
      const createdSessionId = sessionId;
      terminalWindow.location.replace(
        `/@warpgate#/web-ssh/${encodeURIComponent(createdSessionId)}`,
      );
      sessionId = null;
      void logSecureAccessEvent("access", "ssh.target.opened", {
        target: target.name,
        sessionId: createdSessionId,
        originRoute: "/admin/ssh-access",
      });
    } catch (connectError) {
      console.error("Unable to connect to the SSH target:", connectError);
      let message =
        connectError instanceof Error
          ? connectError.message
          : "Unable to start the SSH session.";
      if (sessionId) {
        try {
          await deleteWarpgateWebSshSession(sessionId);
        } catch (cleanupError) {
          console.error(
            "Unable to clean up the SSH session after launch failed:",
            cleanupError,
          );
          message = `${message} The session may still be active because cleanup failed.`;
        }
      }
      if (!terminalWindow.closed) {
        terminalWindow.close();
      }
      setConnectionError(message);
    } finally {
      setConnectingTargetId("");
    }
  }

  return (
    <DashboardLayout>
      <div className="ssh-access-page">
        <div className="admin-page-header">
          <div>
            <h1>SSH Access</h1>
            <p>
              Connect securely to SSH targets available to your account.
            </p>
          </div>

          <button
            className="secondary-action-button"
            onClick={loadTargets}
            disabled={loading}
          >
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>

        {connectionError && (
          <div className="ssh-page-message error" role="alert">
            {connectionError}
          </div>
        )}

        <section className="admin-summary-grid ssh-summary-grid">
          <div className="admin-summary-card">
            <span>SSH Targets</span>
            <strong>{loading ? "—" : targets.length}</strong>
          </div>

          <div className="admin-summary-card">
            <span>SecureAccess SSH Port</span>
            <strong>{warpgateInfo?.ports?.ssh ?? "—"}</strong>
          </div>
        </section>

        <section className="admin-panel">
          <div className="admin-panel-header">
            <div>
              <h2>Available SSH Targets</h2>
              <p>
                Select a target to open a secure browser terminal in a new
                page. Disconnect to close the session and return here.
              </p>
            </div>
          </div>

          <div className="admin-toolbar">
            <div className="admin-search">
              <Search size={15} />
              <input
                type="text"
                placeholder="Search SSH targets..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
          </div>

          {loading && (
            <div className="ssh-page-message">
              Loading SSH targets from SecureAccess...
            </div>
          )}

          {!loading && error && (
            <div className="ssh-page-message error">{error}</div>
          )}

          {!loading && !error && filteredTargets.length === 0 && (
            <div className="ssh-page-message">
              No SSH targets are available in SecureAccess.
            </div>
          )}

          {!loading && !error && filteredTargets.length > 0 && (
            <div className="ssh-target-grid">
              {filteredTargets.map((target) => (
                <div
                  className="ssh-target-card"
                  key={target.id || target.name}
                >
                  <div className="ssh-target-header">
                    <div>
                      <h3>{target.name}</h3>
                      <p className="ssh-target-address">
                        {getAddress(target)}
                      </p>
                    </div>

                    <span className="ssh-status available">
                      Available
                    </span>
                  </div>

                  <div className="ssh-target-details">
                    <div className="ssh-detail-row">
                      <span>Protocol</span>
                      <strong>SSH</strong>
                    </div>
                    <div className="ssh-detail-row">
                      <span>Access Role</span>
                      <strong>{getAccessRole(target)}</strong>
                    </div>
                  </div>

                  <button
                    className="ssh-connect-button"
                    onClick={() => handleConnect(target)}
                    disabled={Boolean(connectingTargetId)}
                    type="button"
                  >
                    <Terminal size={16} />
                    <span>
                      {connectingTargetId === target.id
                        ? "Connecting..."
                        : "Connect"}
                    </span>
                  </button>
                  <button
                    className="ssh-instructions-button"
                    onClick={() => setAccessInstructionsTarget(target)}
                    type="button"
                  >
                    <BookOpen size={15} />
                    <span>Access Instruction</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
      {accessInstructionsTarget && (
        <AccessInstructionsDialog
          info={warpgateInfo}
          onClose={() => setAccessInstructionsTarget(null)}
          target={accessInstructionsTarget}
        />
      )}
    </DashboardLayout>
  );
}