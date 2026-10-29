
import {
  UserRound,
  LogOut,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAppRole } from "../auth/useAppRole";
import { logoutFromWarpgate } from "../api/warpgate";

function Topbar() {
  const { role } = useAppRole();
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const roleLabel = role === "admin"
    ? "Admin"
    : role === "auditor_viewer"
      ? "Auditor/Viewer"
      : "Developer";

  async function handleLogout() {
    setLoggingOut(true);
    setLogoutError("");
    try {
      await logoutFromWarpgate();
      navigate("/", { replace: true });
    } catch (error) {
      console.error("Unable to log out of SecureAccess:", error);
      setLogoutError("Logout failed. Please try again.");
    } finally {
      setLoggingOut(false);
    }
  }

  return (
    <header className="topbar">
      <div className="topbar-page-name">
        <ShieldCheck
          size={17}
          strokeWidth={1.8}
          color="#a78bfa"
        />
        <span>SecureAccess</span>
        <span className="topbar-divider">/</span>
        <span className="topbar-current-page">Dashboard</span>
      </div>

      <div className="topbar-actions">
        <div className="profile-button" aria-label={`${roleLabel} profile`}>
          <UserRound size={15} strokeWidth={1.8} />
          <span>{roleLabel}</span>
        </div>
        <button
          className="logout-button"
          disabled={loggingOut}
          onClick={() => void handleLogout()}
          type="button"
        >
          <LogOut size={15} strokeWidth={1.8} />
          <span>{loggingOut ? "Logging out..." : "Logout"}</span>
        </button>
      </div>
      {logoutError && (
        <span className="logout-error" role="alert">
          {logoutError}
        </span>
      )}
    </header>
  );
}

export default Topbar;
