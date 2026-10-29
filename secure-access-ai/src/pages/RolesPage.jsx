import {
  Plus,
  Search,
  ShieldCheck,
  UserCog,
} from "lucide-react";

import {
  useEffect,
  useCallback,
  useState,
} from "react";

import DashboardLayout from "../layouts/DashboardLayout";
import WarpgateAdminFrame from "../components/WarpgateAdminFrame";
import RowActionsMenu from "../components/RowActionsMenu";

import {
  createWarpgateAccessRole,
  createWarpgateAdminRole,
  deleteWarpgateAccessRole,
  deleteWarpgateAdminRole,
  getWarpgateRoles,
  getWarpgateAdminRoles,
} from "../api/warpgate";
import { logSecureAccessEvent } from "../api/audit";

import "../styles/RolesPage.css";

const ADMIN_PERMISSION_GROUPS = [
  {
    title: "Targets",
    permissions: [
      ["targets_create", "Create targets"],
      ["targets_edit", "Edit targets"],
      ["targets_delete", "Delete targets"],
    ],
  },
  {
    title: "Users",
    permissions: [
      ["users_create", "Create users"],
      ["users_edit", "Edit users"],
      ["users_delete", "Delete users"],
    ],
  },
  {
    title: "Access roles",
    permissions: [
      ["access_roles_create", "Create access roles"],
      ["access_roles_edit", "Edit access roles"],
      ["access_roles_delete", "Delete access roles"],
      ["access_roles_assign", "Assign access roles"],
    ],
  },
  {
    title: "Sessions and recordings",
    permissions: [
      ["sessions_view", "View sessions"],
      ["sessions_terminate", "Terminate sessions"],
      ["recordings_view", "View recordings"],
    ],
  },
  {
    title: "Other",
    permissions: [
      ["tickets_create", "Create tickets"],
      ["tickets_delete", "Delete tickets"],
      ["config_edit", "Edit configuration"],
      ["admin_roles_manage", "Manage admin roles"],
      ["ticket_requests_manage", "Manage ticket requests"],
    ],
  },
];

const EMPTY_ADMIN_PERMISSIONS = Object.fromEntries(
  ADMIN_PERMISSION_GROUPS.flatMap(({ permissions }) =>
    permissions.map(([key]) => [key, false]),
  ),
);

function getRoleDisplayName(role) {
  return role.roleType === "Admin Role" && role.name === "warpgate:admin"
    ? "SecureAccess Administrator"
    : role.name;
}

function getRoleDisplayDescription(role) {
  return role.roleType === "Admin Role" &&
    role.name === "warpgate:admin" &&
    role.description === "Built-in admin role"
    ? "Built-in SecureAccess administrator role"
    : role.description;
}

function RolesPage() {
  const [accessRoles, setAccessRoles] = useState([]);
  const [adminRoles, setAdminRoles] = useState([]);

  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [roleEditor, setRoleEditor] = useState(null);
  const [roleType, setRoleType] = useState("access");
  const [roleName, setRoleName] = useState("");
  const [roleDescription, setRoleDescription] = useState("");
  const [isDefault, setIsDefault] = useState(false);
  const [adminPermissions, setAdminPermissions] = useState(EMPTY_ADMIN_PERMISSIONS);
  const [saving, setSaving] = useState(false);
  const [createError, setCreateError] = useState("");

  const loadRoles = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [
        realAccessRoles,
        realAdminRoles,
      ] = await Promise.all([
        getWarpgateRoles(),
        getWarpgateAdminRoles(),
      ]);

      setAccessRoles(
        Array.isArray(realAccessRoles)
          ? realAccessRoles
          : []
      );

      setAdminRoles(
        Array.isArray(realAdminRoles)
          ? realAdminRoles
          : []
      );

    } catch (err) {
      console.error("Failed loading roles:", err);
      setError(err instanceof Error ? err.message : "Unable to load roles from SecureAccess.");

    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadRoles();
    }, 0);
    return () => window.clearTimeout(timeoutId);
  }, [loadRoles]);

  useEffect(() => {
    if (!isCreateOpen) {
      return undefined;
    }

    function handleKeyDown(event) {
      if (event.key === "Escape" && !saving) {
        setIsCreateOpen(false);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isCreateOpen, saving]);

  function openCreateDialog() {
    setRoleType("access");
    setRoleName("");
    setRoleDescription("");
    setIsDefault(false);
    setAdminPermissions(EMPTY_ADMIN_PERMISSIONS);
    setCreateError("");
    setIsCreateOpen(true);
    void logSecureAccessEvent("roles", "role.create.opened");
  }

  async function handleCreateRole(event) {
    event.preventDefault();
    const name = roleName.trim();
    if (!name) {
      setCreateError("Enter a role name.");
      return;
    }

    setSaving(true);
    setCreateError("");
    try {
      if (roleType === "access") {
        await createWarpgateAccessRole({
          name,
          description: roleDescription.trim(),
          is_default: isDefault,
        });
      } else {
        await createWarpgateAdminRole({
          name,
          description: roleDescription.trim(),
          ...adminPermissions,
        });
      }
      void logSecureAccessEvent("roles", "role.created", {
        roleType,
        name,
      });
      setIsCreateOpen(false);
      await loadRoles();
    } catch (err) {
      console.error("Failed creating Warpgate role:", err);
      setCreateError(
        err instanceof Error ? err.message : "Unable to create this role.",
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleDeleteRole(role) {
    if (!window.confirm(`Delete ${role.roleType.toLowerCase()} "${role.name}"?`)) {
      return;
    }
    setError("");
    try {
      if (role.roleType === "Access Role") {
        await deleteWarpgateAccessRole(role.id);
      } else {
        await deleteWarpgateAdminRole(role.id);
      }
      void logSecureAccessEvent("roles", "role.deleted", {
        roleType: role.roleType,
        name: role.name,
      });
      await loadRoles();
    } catch (err) {
      console.error("Failed deleting Warpgate role:", err);
      setError(err instanceof Error ? err.message : "Unable to delete this role.");
    }
  }


  const combinedRoles = [
    ...accessRoles.map((role) => ({
      ...role,
      roleType: "Access Role",
    })),

    ...adminRoles.map((role) => ({
      ...role,
      roleType: "Admin Role",
    })),
  ];


  const filteredRoles =
    combinedRoles.filter((role) => {
      const query =
        search.trim().toLowerCase();

      if (!query) {
        return true;
      }

      return (
        role.name
          ?.toLowerCase()
          .includes(query) ||

        role.description
          ?.toLowerCase()
          .includes(query)
      );
    });


  return (
    <DashboardLayout>

      <div className="roles-page-header">

        <div>
          <h1>
            Roles & Permissions
          </h1>

          <p>
            Manage SecureAccess roles and administrative permissions.
          </p>
        </div>

        <button className="add-role-button" onClick={openCreateDialog} type="button">
          <Plus size={16} />
          Create Role
        </button>

      </div>


      <section className="roles-summary">

        <div className="role-summary-card">
          <div className="role-summary-icon">
            <ShieldCheck size={18} />
          </div>

          <div>
            <span>
              Total Roles
            </span>

            <strong>
              {combinedRoles.length}
            </strong>
          </div>
        </div>


        <div className="role-summary-card">
          <div className="role-summary-icon">
            <ShieldCheck size={18} />
          </div>

          <div>
            <span>
              Access Roles
            </span>

            <strong>
              {accessRoles.length}
            </strong>
          </div>
        </div>


        <div className="role-summary-card">
          <div className="role-summary-icon">
            <UserCog size={18} />
          </div>

          <div>
            <span>
              Admin Roles
            </span>

            <strong>
              {adminRoles.length}
            </strong>
          </div>
        </div>


        <div className="role-summary-card">
          <div className="role-summary-icon">
            <ShieldCheck size={18} />
          </div>

          <div>
            <span>
              Source
            </span>

            <strong
              style={{
                fontSize: "14px",
              }}
            >
              SecureAccess
            </strong>
          </div>
        </div>

      </section>


      <section className="roles-panel">

        <div className="roles-toolbar">

          <div className="roles-search">
            <Search size={16} />

            <input
              type="text"
              placeholder="Search roles..."
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
              padding: "30px",
              textAlign: "center",
              color: "#667085",
              fontSize: "11px",
            }}
          >
            Loading SecureAccess roles...
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
          <div className="roles-table-wrapper">

            <table className="roles-table">

              <thead>
                <tr>
                  <th>Role</th>
                  <th>Type</th>
                  <th>Description</th>
                  <th>ID</th>
                  <th></th>
                </tr>
              </thead>

              <tbody>

                {filteredRoles.map(
                  (role) => (

                    <tr
                      key={`${role.roleType}-${role.id}`}
                    >

                      <td>

                        <div className="role-name-cell">

                          <div
                            className={
                              role.roleType ===
                              "Admin Role"
                                ? "role-icon admin"
                                : "role-icon access"
                            }
                          >

                            {role.roleType ===
                            "Admin Role" ? (
                              <UserCog size={16} />
                            ) : (
                              <ShieldCheck size={16} />
                            )}

                          </div>

                          <strong>
                            {getRoleDisplayName(role)}
                          </strong>

                        </div>

                      </td>


                      <td>

                        <span
                          className={
                            role.roleType ===
                            "Admin Role"
                              ? "role-type-badge admin"
                              : "role-type-badge access"
                          }
                        >
                          {role.roleType}
                        </span>

                      </td>


                      <td className="role-description-cell">

                        {getRoleDisplayDescription(role) || "—"}

                      </td>


                      <td className="role-description-cell">

                        {role.id}

                      </td>


                      <td className="role-actions-cell">

                        <RowActionsMenu
                          canDelete={
                            role.roleType !== "Admin Role" ||
                            role.name !== "warpgate:admin"
                          }
                          label={getRoleDisplayName(role)}
                          onDelete={() => void handleDeleteRole(role)}
                          onEdit={() => {
                            const rolePath =
                              role.roleType === "Access Role"
                                ? "access-roles"
                                : "admin-roles";
                            setRoleEditor({
                              title: `Edit ${getRoleDisplayName(role)}`,
                              src: `/@warpgate/admin#/config/${rolePath}/${encodeURIComponent(role.id)}`,
                            });
                          }}
                        />

                      </td>

                    </tr>

                  )
                )}


                {filteredRoles.length === 0 && (

                  <tr>

                    <td
                      colSpan="5"
                      style={{
                        textAlign: "center",
                        height: "80px",
                        color: "#667085",
                      }}
                    >
                      No roles found.
                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>
        )}


        {!loading && !error && (

          <div className="roles-footer">

            <span>
              Showing {filteredRoles.length} roles
            </span>

            <button onClick={() => void loadRoles()} type="button">
              Refresh
            </button>

          </div>

        )}

      </section>

      {isCreateOpen && (
        <div
          className="role-modal-backdrop"
          onClick={(event) => {
            if (event.target === event.currentTarget && !saving) {
              setIsCreateOpen(false);
            }
          }}
        >
          <section
            aria-labelledby="create-role-title"
            aria-modal="true"
            className="role-modal"
            role="dialog"
          >
            <header className="role-modal-header">
              <div>
                <h2 id="create-role-title">Create SecureAccess role</h2>
                <p>Choose which type of role you want to create.</p>
              </div>
              <button
                aria-label="Close role dialog"
                className="role-modal-close"
                disabled={saving}
                onClick={() => setIsCreateOpen(false)}
                type="button"
              >
                ×
              </button>
            </header>

            <form className="role-modal-form" onSubmit={handleCreateRole}>
              <div className="role-type-choice" aria-label="Role type">
                <button
                  aria-pressed={roleType === "access"}
                  className={roleType === "access" ? "active" : ""}
                  onClick={() => setRoleType("access")}
                  type="button"
                >
                  Access role
                </button>
                <button
                  aria-pressed={roleType === "admin"}
                  className={roleType === "admin" ? "active" : ""}
                  onClick={() => setRoleType("admin")}
                  type="button"
                >
                  Admin role
                </button>
              </div>

              <label className="role-form-field">
                Role name
                <input
                  autoFocus
                  maxLength={128}
                  onChange={(event) => setRoleName(event.target.value)}
                  required
                  value={roleName}
                />
              </label>
              <label className="role-form-field">
                Description
                <textarea
                  maxLength={1000}
                  onChange={(event) => setRoleDescription(event.target.value)}
                  rows={2}
                  value={roleDescription}
                />
              </label>

              {roleType === "access" ? (
                <label className="role-permission-option">
                  <input
                    checked={isDefault}
                    onChange={(event) => setIsDefault(event.target.checked)}
                    type="checkbox"
                  />
                  Assign this access role to new users by default
                </label>
              ) : (
                <div className="admin-permission-groups">
                  {ADMIN_PERMISSION_GROUPS.map(({ title, permissions }) => (
                    <fieldset className="admin-permission-group" key={title}>
                      <legend>{title}</legend>
                      {permissions.map(([key, label]) => (
                        <label className="role-permission-option" key={key}>
                          <input
                            checked={adminPermissions[key]}
                            onChange={(event) =>
                              setAdminPermissions((current) => ({
                                ...current,
                                [key]: event.target.checked,
                              }))
                            }
                            type="checkbox"
                          />
                          {label}
                        </label>
                      ))}
                    </fieldset>
                  ))}
                </div>
              )}

              {roleEditor && (
                <div
                  className="role-modal-backdrop"
                  onClick={(event) => {
                    if (event.target === event.currentTarget) {
                      setRoleEditor(null);
                      void loadRoles();
                    }
                  }}
                >
                  <section
                    aria-label={roleEditor.title}
                    aria-modal="true"
                    className="role-modal role-editor-modal"
                    role="dialog"
                  >
                    <header className="role-modal-header">
                      <h2>{roleEditor.title}</h2>
                      <button
                        aria-label="Close role editor"
                        className="role-modal-close"
                        onClick={() => {
                          setRoleEditor(null);
                          void loadRoles();
                        }}
                        type="button"
                      >
                        ×
                      </button>
                    </header>
                    <WarpgateAdminFrame
                      className="role-editor-frame"
                      src={roleEditor.src}
                      title={roleEditor.title}
                    />
                  </section>
                </div>
              )}

              {createError && (
                <div className="role-form-error" role="alert">
                  {createError}
                </div>
              )}
              <footer className="role-modal-footer">
                <button
                  className="role-cancel-button"
                  disabled={saving}
                  onClick={() => setIsCreateOpen(false)}
                  type="button"
                >
                  Cancel
                </button>
                <button className="role-submit-button" disabled={saving} type="submit">
                  {saving ? "Creating..." : "Create role"}
                </button>
              </footer>
            </form>
          </section>
        </div>
      )}

    </DashboardLayout>
  );
}

export default RolesPage;