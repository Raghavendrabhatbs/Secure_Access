import DashboardLayout from "../layouts/DashboardLayout";
import "../styles/AdminPages.css";

function SettingsPage() {
  return (
    <DashboardLayout>

      <div className="admin-page-header">
        <div>
          <h1>Settings</h1>
          <p>
            Configure SecureAccess system preferences.
          </p>
        </div>
      </div>


      <div className="settings-grid">

        <aside className="settings-nav">

          <button className="active">
            General
          </button>

          <button>
            Authentication
          </button>

          <button>
            Recording
          </button>

          <button>
            Security
          </button>

          <button>
            Notifications
          </button>

        </aside>


        <section className="settings-content">

          <h2>General Settings</h2>

          <p>
            Basic configuration for the SecureAccess platform.
          </p>


          <div className="setting-row">

            <div>
              <strong>System Name</strong>
              <span>Name displayed across the administration interface.</span>
            </div>

            <span className="setting-value">
              SecureAccess
            </span>

          </div>


          <div className="setting-row">

            <div>
              <strong>Session Recording</strong>
              <span>Automatically record privileged sessions.</span>
            </div>

            <span className="status-badge success">
              Enabled
            </span>

          </div>


          <div className="setting-row">

            <div>
              <strong>Audit Logging</strong>
              <span>Record administrative and security events.</span>
            </div>

            <span className="status-badge success">
              Enabled
            </span>

          </div>


          <div className="setting-row">

            <div>
              <strong>Authentication Provider</strong>
              <span>Current authentication backend.</span>
            </div>

            <span className="setting-value">
              SecureAccess
            </span>

          </div>

        </section>

      </div>

    </DashboardLayout>
  );
}

export default SettingsPage;