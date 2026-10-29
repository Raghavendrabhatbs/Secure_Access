import { useEffect, useMemo, useState } from "react";
import {
  Globe2,
  Search,
  ExternalLink,
  RefreshCw,
} from "lucide-react";

import DashboardLayout from "../layouts/DashboardLayout";
import {
  getAccessibleWarpgateTargets,
  getWarpgateAccessOrigin,
} from "../api/warpgate";
import { logSecureAccessEvent } from "../api/audit";

import "../styles/AdminPages.css";


function isWebTarget(target) {
  return (
    (target.kind || target.options?.kind)
      ?.toString()
      .toLowerCase() === "http"
  );
}


function getTargetAddress(target) {
  return target.options?.url || "—";
}


function WebAccessPage() {
  const [targets, setTargets] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  useEffect(() => {
    loadTargets();
  }, []);


  async function loadTargets() {
    try {
      setLoading(true);
      setError("");

      const data = await getAccessibleWarpgateTargets();

      const allTargets =
        Array.isArray(data) ? data : [];

      const webTargets =
        allTargets.filter(isWebTarget);

      console.log(
        "Web access targets:",
        webTargets
      );

      setTargets(webTargets);

    } catch (err) {
      console.error(
        "Failed loading Web targets:",
        err
      );

      setError(
        "Unable to load Web targets from SecureAccess."
      );

    } finally {
      setLoading(false);
    }
  }


  const filteredTargets =
    useMemo(() => {
      const query =
        search.trim().toLowerCase();

      if (!query) {
        return targets;
      }

      return targets.filter(
        (target) =>
          target.name
            ?.toLowerCase()
            .includes(query) ||

          target.description
            ?.toLowerCase()
            .includes(query) ||

          target.options?.url
            ?.toLowerCase()
            .includes(query)
      );

    }, [targets, search]);


  function openTarget(target) {
    void logSecureAccessEvent("access", "web.target.opened", {
      target: target.name,
    });
    const url =
      `${getWarpgateAccessOrigin(window.location.hostname)}/?warpgate-target=${encodeURIComponent(
        target.name
      )}`;

    window.open(
      url,
      "_blank",
      "noopener,noreferrer"
    );
  }


  return (
    <DashboardLayout>

      <div className="admin-page-header">

        <div>
          <h1>Web Access</h1>

          <p>
            Access authorized web applications securely through SecureAccess.
          </p>
        </div>


        <button
          className="secondary-action-button"
          onClick={loadTargets}
        >
          <RefreshCw size={14} />
          Refresh
        </button>

      </div>


      <section className="admin-summary-grid web-summary-grid">

        <div className="admin-summary-card">
          <span>
            Web Targets
          </span>

          <strong>
            {loading ? "—" : targets.length}
          </strong>
        </div>


        <div className="admin-summary-card">
          <span>
            Gateway Port
          </span>

          <strong>
            8888
          </strong>
        </div>

      </section>


      <section className="admin-panel">

        <div className="admin-panel-header">

          <div>
            <h2>
              Available Web Targets
            </h2>

            <p>
              Select a target to open it through the secure gateway.
            </p>
          </div>

        </div>


        <div className="admin-toolbar">

          <div className="admin-search">

            <Search size={15} />

            <input
              type="text"
              placeholder="Search web targets..."
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value
                )
              }
            />

          </div>

        </div>


        {loading && (
          <div
            style={{
              padding: "35px",
              textAlign: "center",
              color: "#667085",
            }}
          >
            Loading Web targets...
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

            <table className="admin-table">

              <thead>
                <tr>
                  <th>Application</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Description</th>
                  <th>Action</th>
                </tr>
              </thead>


              <tbody>

                {filteredTargets.map(
                  (target) => (

                    <tr key={target.id}>

                      <td>

                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "8px",
                          }}
                        >
                          <Globe2 size={15} />

                          <strong>
                            {target.name}
                          </strong>
                        </div>

                      </td>


                      <td className="table-muted">
                        {getTargetAddress(
                          target
                        )}
                      </td>


                      <td>
                        <span className="type-badge web">
                          WEB
                        </span>
                      </td>


                      <td className="table-muted">
                        {target.description ||
                          "—"}
                      </td>


                      <td>

                        <button
                          className="secondary-action-button"
                          onClick={() =>
                            openTarget(target)
                          }
                        >
                          <ExternalLink
                            size={13}
                          />

                          Open
                        </button>

                      </td>

                    </tr>

                  )
                )}


                {filteredTargets.length ===
                  0 && (

                  <tr>

                    <td
                      colSpan="5"
                      style={{
                        height: "90px",
                        textAlign: "center",
                        color: "#667085",
                      }}
                    >
                      No Web targets found.
                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        )}

      </section>

    </DashboardLayout>
  );
}


export default WebAccessPage;