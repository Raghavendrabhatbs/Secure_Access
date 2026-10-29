import { NavLink } from "react-router-dom";
import {
  Activity,
  ClipboardList,
  FolderTree,
  Globe2,
  LayoutDashboard,
  PlayCircle,
  Server,
  ShieldCheck,
  Sparkles,
  Terminal,
  Users,
} from "lucide-react";
import { useAppRole } from "../auth/useAppRole";

function Sidebar() {
  const { role } = useAppRole();
  const isAdmin = role === "admin";
  const isDeveloper = role === "developer";
  const canReadRecordings = isAdmin || isDeveloper || role === "auditor_viewer";
  const dashboardPath = isAdmin
    ? "/admin"
    : isDeveloper
      ? "/developer"
      : "/viewer";

  const linkClass = ({ isActive }) =>
    isActive ? "sidebar-link active" : "sidebar-link";

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldCheck size={23} strokeWidth={1.8} />
        <span>SecureAccess</span>
      </div>

      <nav className="sidebar-nav">
        <NavLink to={dashboardPath} end className={linkClass}>
          <LayoutDashboard size={18} strokeWidth={1.7} />
          <span>Dashboard</span>
        </NavLink>

        {(isAdmin || isDeveloper) && (
          <div className="sidebar-section">
            <div className="sidebar-section-title">ACCESS</div>
            <NavLink to="/admin/ssh-access" className={linkClass}>
              <Terminal size={18} strokeWidth={1.7} />
              <span>SSH Access</span>
            </NavLink>
            <NavLink to="/admin/web-access" className={linkClass}>
              <Globe2 size={18} strokeWidth={1.7} />
              <span>Web Access</span>
            </NavLink>
          </div>
        )}

        <div className="sidebar-section">
          <div className="sidebar-section-title">MONITORING</div>
          {isAdmin && (
            <NavLink to="/admin/sessions" className={linkClass}>
              <Activity size={18} strokeWidth={1.7} />
              <span>Sessions</span>
            </NavLink>
          )}
          {canReadRecordings && (
            <NavLink to="/admin/recordings" className={linkClass}>
              <PlayCircle size={18} strokeWidth={1.7} />
              <span>Recordings</span>
            </NavLink>
          )}
          {(isAdmin || isDeveloper || role === "auditor_viewer") && (
            <NavLink to="/admin/ai-assistant" className={linkClass}>
              <Sparkles size={18} strokeWidth={1.7} />
              <span>AI Assistant</span>
            </NavLink>
          )}
        </div>

        {isAdmin && (
          <div className="sidebar-section">
            <div className="sidebar-section-title">ADMINISTRATION</div>
            <NavLink to="/admin/users" className={linkClass}>
              <Users size={18} strokeWidth={1.7} />
              <span>Users</span>
            </NavLink>
            <NavLink to="/admin/roles" className={linkClass}>
              <ShieldCheck size={18} strokeWidth={1.7} />
              <span>Roles &amp; Permissions</span>
            </NavLink>
            <NavLink to="/admin/targets" className={linkClass}>
              <Server size={18} strokeWidth={1.7} />
              <span>Targets</span>
            </NavLink>
            <NavLink to="/admin/target-groups" className={linkClass}>
              <FolderTree size={18} strokeWidth={1.7} />
              <span>Target groups</span>
            </NavLink>
          </div>
        )}

        {(isAdmin || role === "auditor_viewer") && (
          <div className="sidebar-section">
            <div className="sidebar-section-title">AUDIT</div>
            <NavLink to="/admin/audit-logs" className={linkClass}>
              <ClipboardList size={18} strokeWidth={1.7} />
              <span>Audit Logs</span>
            </NavLink>
          </div>
        )}
      </nav>

    </aside>
  );
}

export default Sidebar;
