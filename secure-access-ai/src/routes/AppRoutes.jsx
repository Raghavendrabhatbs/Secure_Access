import {
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { useAppRole } from "../auth/useAppRole";

import Login from "../pages/Login";

import AdminDashboard from "../pages/AdminDashboard";
import UsersPage from "../pages/UsersPage";
import RolesPage from "../pages/RolesPage";
import WarpgateAdminEmbedPage from "../pages/WarpgateAdminEmbedPage";

import TargetsPage from "../pages/TargetsPage";
import SessionsPage from "../pages/SessionsPage";
import RecordingsPage from "../pages/RecordingsPage";
import AuditLogsPage from "../pages/AuditLogsPage";

import SSHAccessPage from "../pages/SSHAccessPage";
import WebAccessPage from "../pages/WebAccessPage";

import AIAssistantPage from "../pages/AIAssistantPage";
import SettingsPage from "../pages/SettingsPage";

import DeveloperDashboard from "../pages/DeveloperDashboard";
import ViewerDashboard from "../pages/ViewerDashboard";

import ReplayPage from "../pages/ReplayPage";
import WatchPage from "../pages/WatchPage";

const ADMIN = ["admin"];
const DEVELOPER = ["admin", "developer"];
const AUDIT_READERS = ["admin", "auditor_viewer"];
const RECORDING_READERS = ["admin", "developer", "auditor_viewer"];

function RoleRoute({ allowedRoles, children }) {
  const { role, loading } = useAppRole();
  if (loading) {
    return <div className="route-loading">Checking access...</div>;
  }
  if (!role) {
    return <Navigate replace to="/" />;
  }
  if (!allowedRoles.includes(role)) {
    const home = role === "admin"
      ? "/admin"
      : role === "developer"
        ? "/developer"
        : "/viewer";
    return <Navigate replace to={home} />;
  }
  return children;
}

function AppRoutes() {
  return (
    <Routes>

      {/* LOGIN */}

      <Route
        path="/"
        element={<Login />}
      />


      {/* ADMIN */}

      <Route
        path="/admin"
        element={<RoleRoute allowedRoles={ADMIN}><AdminDashboard /></RoleRoute>}
      />

      <Route
        path="/admin/users"
        element={<RoleRoute allowedRoles={ADMIN}><UsersPage /></RoleRoute>}
      />

      <Route
        path="/admin/roles"
        element={<RoleRoute allowedRoles={ADMIN}><RolesPage /></RoleRoute>}
      />

      <Route
        path="/admin/targets"
        element={<RoleRoute allowedRoles={ADMIN}><TargetsPage /></RoleRoute>}
      />

      <Route
        path="/admin/target-groups"
        element={
          <RoleRoute allowedRoles={ADMIN}>
            <WarpgateAdminEmbedPage
              title="Target groups"
              description="Organize SecureAccess targets into groups."
              warpgatePath="/config/target-groups"
            />
          </RoleRoute>
        }
      />

      <Route
        path="/admin/tickets"
        element={
          <RoleRoute allowedRoles={ADMIN}>
            <WarpgateAdminEmbedPage
              title="Tickets"
              description="Manage temporary access tickets in SecureAccess."
              warpgatePath="/config/tickets"
            />
          </RoleRoute>
        }
      />

      <Route
        path="/admin/sessions"
        element={<RoleRoute allowedRoles={ADMIN}><SessionsPage /></RoleRoute>}
      />

      <Route
        path="/admin/watch"
        element={<RoleRoute allowedRoles={ADMIN}><WatchPage /></RoleRoute>}
      />

      <Route
        path="/admin/recordings"
        element={<RoleRoute allowedRoles={RECORDING_READERS}><RecordingsPage /></RoleRoute>}
      />


      <Route
  path="/admin/recordings/replay"
  element={<RoleRoute allowedRoles={RECORDING_READERS}><ReplayPage /></RoleRoute>}
/>

      <Route
        path="/admin/audit-logs"
        element={<RoleRoute allowedRoles={AUDIT_READERS}><AuditLogsPage /></RoleRoute>}
      />

      <Route
        path="/admin/ssh-access"
        element={<RoleRoute allowedRoles={DEVELOPER}><SSHAccessPage /></RoleRoute>}
      />

      <Route
        path="/admin/web-access"
        element={<RoleRoute allowedRoles={DEVELOPER}><WebAccessPage /></RoleRoute>}
      />

      <Route
        path="/admin/ai-assistant"
        element={
          <RoleRoute allowedRoles={RECORDING_READERS}>
            <AIAssistantPage />
          </RoleRoute>
        }
      />

      <Route
        path="/admin/settings"
        element={<RoleRoute allowedRoles={ADMIN}><SettingsPage /></RoleRoute>}
      />


      {/* OTHER ROLE DASHBOARDS */}

      <Route
        path="/developer"
        element={<RoleRoute allowedRoles={["developer"]}><DeveloperDashboard /></RoleRoute>}
      />

      <Route
        path="/viewer"
        element={<RoleRoute allowedRoles={["auditor_viewer"]}><ViewerDashboard /></RoleRoute>}
      />

    </Routes>
  );
}

export default AppRoutes;