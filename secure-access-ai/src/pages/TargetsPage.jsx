import {
  Plus,
  Search,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import DashboardLayout from "../layouts/DashboardLayout";
import WarpgateAdminFrame from "../components/WarpgateAdminFrame";
import RowActionsMenu from "../components/RowActionsMenu";

import {
  deleteWarpgateTarget,
  getWarpgateTargets,
  getWarpgateTargetRoles,
} from "../api/warpgate";

import "../styles/AdminPages.css";

function getProtocol(target) {
  const kind =
    target.options?.kind
      ?.toString()
      .toLowerCase();

  switch (kind) {
    case "ssh":
      return "SSH";

    case "http":
      return "WEB";

    case "mysql":
      return "MYSQL";

    case "postgres":
    case "postgresql":
      return "POSTGRES";

    case "kubernetes":
      return "KUBERNETES";

    case "rdp":
      return "RDP";

    case "vnc":
      return "VNC";

    default:
      return "UNKNOWN";
  }
}
function getTargetAddress(target) {
  const options = target.options;

  if (!options) {
    return "—";
  }

  if (options.url) {
    return options.url;
  }

  if (options.host) {
    return options.port
      ? `${options.host}:${options.port}`
      : options.host;
  }

  return "—";
}

function TargetsPage() {

  const [targets, setTargets] =
    useState([]);

  const [search, setSearch] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [isAddTargetOpen, setIsAddTargetOpen] =
    useState(false);
  const [targetEditor, setTargetEditor] = useState(null);

  const loadTargets = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const realTargets = await getWarpgateTargets();
      const targetArray = Array.isArray(realTargets) ? realTargets : [];
      const targetsWithRoles = await Promise.all(
        targetArray.map(async (target) => {
          try {
            const roles = await getWarpgateTargetRoles(target.id);
            return {
              ...target,
              roles: Array.isArray(roles) ? roles : [],
            };
          } catch (roleError) {
            console.error(
              `Failed loading roles for target ${target.name}`,
              roleError,
            );
            return { ...target, roles: [] };
          }
        }),
      );
      setTargets(targetsWithRoles);
    } catch (err) {
      console.error("Failed loading targets:", err);
      setError(
        err instanceof Error
          ? err.message
          : "Unable to load targets from SecureAccess.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  async function handleDeleteTarget(target) {
    if (!window.confirm(`Delete target "${target.name}"? Its active tickets and target access will also be removed.`)) {
      return;
    }
    setError("");
    try {
      await deleteWarpgateTarget(target.id);
      await loadTargets();
    } catch (err) {
      console.error("Failed deleting Warpgate target:", err);
      setError(err instanceof Error ? err.message : "Unable to delete this target.");
    }
  }

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadTargets();
    }, 0);
    return () => window.clearTimeout(timeoutId);
  }, [loadTargets]);

  useEffect(() => {
    if (!isAddTargetOpen) {
      return undefined;
    }
    function handleKeyDown(event) {
      if (event.key === "Escape") {
        setIsAddTargetOpen(false);
        setTargetEditor(null);
        void loadTargets();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isAddTargetOpen, loadTargets]);


  const filteredTargets =
    targets.filter((target) => {

      const query =
        search
          .trim()
          .toLowerCase();


      if (!query) {
        return true;
      }


      return (
        target.name
          ?.toLowerCase()
          .includes(query) ||

        target.description
          ?.toLowerCase()
          .includes(query)
      );

    });


  const sshCount =
    targets.filter(
      (target) =>
        getProtocol(target) === "SSH"
    ).length;


  const webCount =
    targets.filter(
      (target) =>
        getProtocol(target) === "WEB"
    ).length;


  return (
    <DashboardLayout>

      <div className="admin-page-header">

        <div>

          <h1>
            Targets
          </h1>

          <p>
            Manage protected infrastructure and web targets from SecureAccess.
          </p>

        </div>


        <button
          className="primary-action-button"
          onClick={() => {
            setTargetEditor({
              title: "Add Target",
              src: "/@warpgate/admin#/config/targets/create",
            });
            setIsAddTargetOpen(true);
          }}
          type="button"
        >

          <Plus size={15} />

          Add Target

        </button>

      </div>


      <section className="admin-summary-grid">

        <div className="admin-summary-card">

          <span>
            Total Targets
          </span>

          <strong>
            {targets.length}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            SSH Targets
          </span>

          <strong>
            {sshCount}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            Web Targets
          </span>

          <strong>
            {webCount}
          </strong>

        </div>


        <div className="admin-summary-card">

          <span>
            Other Protocols
          </span>

          <strong>
            {Math.max(
              0,
              targets.length -
                sshCount -
                webCount
            )}
          </strong>

        </div>

      </section>


      <section className="admin-panel">

        <div className="admin-toolbar">

          <div className="admin-toolbar-left">

            <div className="admin-search">

              <Search size={15} />

              <input
                type="text"
                placeholder="Search targets..."
                value={search}
                onChange={(event) =>
                  setSearch(
                    event.target.value
                  )
                }
              />

            </div>

          </div>

        </div>


        {loading && (

          <div
            style={{
              padding: "30px",
              textAlign: "center",
              color: "#667085",
              fontSize: "11px",
            }}
          >
            Loading SecureAccess targets...
          </div>

        )}


        {!loading && error && (

          <div
            style={{
              padding: "30px",
              textAlign: "center",
              color: "#b42318",
              fontSize: "11px",
            }}
          >
            {error}
          </div>

        )}


        {!loading && !error && (

          <div className="admin-table-wrapper">

            <table className="admin-table">

              <thead>

                <tr>
                  <th>Target</th>
                  <th>Address</th>
                  <th>Protocol</th>
                  <th>Access Roles</th>
                  <th>Description</th>
                  <th></th>
                </tr>

              </thead>


              <tbody>

                {filteredTargets.map(
                  (target) => {

                    const protocol =
                      getProtocol(target);


                    return (

                      <tr key={target.id}>

                        <td className="table-primary">
                          {target.name}
                        </td>


                        <td className="table-muted">
                          {getTargetAddress(
                            target
                          )}
                        </td>


                        <td>

                          <span
                            className={
                              protocol === "SSH"
                                ? "type-badge ssh"
                                : protocol === "WEB"
                                ? "type-badge web"
                                : "type-badge access"
                            }
                          >
                            {protocol}
                          </span>

                        </td>


                        <td>

                          {target.roles.length >
                          0 ? (

                            target.roles.map(
                              (role) => (

                                <span
                                  key={role.id}
                                  className="type-badge access"
                                  style={{
                                    marginRight:
                                      "4px",
                                  }}
                                >
                                  {role.name}
                                </span>

                              )
                            )

                          ) : (

                            <span className="table-muted">
                              —
                            </span>

                          )}

                        </td>


                        <td className="table-muted">

                          {target.description ||
                            "—"}

                        </td>


                        <td className="table-actions">

                          <RowActionsMenu
                            label={target.name}
                            onDelete={() => void handleDeleteTarget(target)}
                            onEdit={() => {
                              setTargetEditor({
                                title: `Edit ${target.name}`,
                                src: `/@warpgate/admin#/config/targets/${encodeURIComponent(target.id)}`,
                              });
                              setIsAddTargetOpen(true);
                            }}
                          />

                        </td>

                      </tr>

                    );

                  }
                )}


                {filteredTargets.length ===
                  0 && (

                  <tr>

                    <td
                      colSpan="6"
                      style={{
                        textAlign:
                          "center",

                        height: "80px",

                        color:
                          "#667085",
                      }}
                    >
                      No targets found.
                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        )}


        {!loading && !error && (

          <div className="admin-panel-footer">

            <span>
              Showing{" "}
              {filteredTargets.length} of{" "}
              {targets.length} targets
            </span>

            <button onClick={() => void loadTargets()} type="button">
              Refresh
            </button>

          </div>

        )}

      </section>

      {isAddTargetOpen && (
        <div
          className="warpgate-target-modal-backdrop"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              setIsAddTargetOpen(false);
              setTargetEditor(null);
              void loadTargets();
            }
          }}
        >
          <section
            aria-label="Add target with SecureAccess"
            aria-modal="true"
            className="warpgate-target-modal"
            role="dialog"
          >
            <div className="warpgate-target-modal-header">
              <h2>{targetEditor?.title || "Add Target"}</h2>
              <button
                aria-label="Close Add Target"
                className="warpgate-target-modal-close"
                onClick={() => {
                  setIsAddTargetOpen(false);
                  setTargetEditor(null);
                  void loadTargets();
                }}
                type="button"
              >
                ×
              </button>
            </div>
            <WarpgateAdminFrame
              className="warpgate-target-modal-frame"
              src={targetEditor?.src || "/@warpgate/admin#/config/targets/create"}
              title="SecureAccess target configuration"
            />
          </section>
        </div>
      )}

    </DashboardLayout>
  );
}

export default TargetsPage;