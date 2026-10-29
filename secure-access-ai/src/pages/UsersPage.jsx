import {
  Search,
  Plus,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import DashboardLayout from "../layouts/DashboardLayout";
import { logSecureAccessEvent } from "../api/audit";
import WarpgateAdminFrame from "../components/WarpgateAdminFrame";
import RowActionsMenu from "../components/RowActionsMenu";

import {
  deleteWarpgateUser,
  getWarpgateUsers,
  getWarpgateUserRoles,
  getWarpgateUserAdminRoles,
  getWarpgateUserApplicationRole,
  setWarpgateUserApplicationRole,
} from "../api/warpgate";

import "../styles/UsersPage.css";


function UsersPage() {

  const [users, setUsers] = useState([]);

  const [search, setSearch] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [isAddUserOpen, setIsAddUserOpen] = useState(false);
  const [userEditor, setUserEditor] = useState(null);
  const [updatingRoleUserId, setUpdatingRoleUserId] = useState("");

  const loadUsers = useCallback(async () => {

    try {

      setLoading(true);
      setError("");

      /*
       * First retrieve the real SecureAccess users.
       */

      const warpgateUsers =
        await getWarpgateUsers();


      /*
       * Now retrieve the access roles and admin roles
       * associated with every user.
       */

      const usersWithRoles =
        await Promise.all(

          warpgateUsers.map(
            async (user) => {

              const [
                accessRoles,
                adminRoles,
                applicationRole,
              ] = await Promise.all([

                  getWarpgateUserRoles(
                    user.id
                  ),

                  getWarpgateUserAdminRoles(
                    user.id
                  ),

                  getWarpgateUserApplicationRole(
                    user.id
                  ),

                ]);

              return {
                ...user,
                accessRoles: accessRoles || [],
                adminRoles: adminRoles || [],
                applicationRole: applicationRole.application_role,
              };

            }
          )

        );


      console.log(
        "Warpgate users:",
        usersWithRoles
      );


      setUsers(usersWithRoles);

    } catch (err) {

      console.error(
        "Failed loading users:",
        err
      );

      setError(
        "Unable to load users from SecureAccess."
      );

    } finally {

      setLoading(false);

    }

  }, []);

  const closeAddUser = useCallback(() => {
    setIsAddUserOpen(false);
    setUserEditor(null);
    loadUsers();
  }, [loadUsers]);

  async function handleDeleteUser(user) {
    if (!window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) {
      return;
    }
    setError("");
    try {
      await deleteWarpgateUser(user.id);
      void logSecureAccessEvent("users", "user.deleted", { username: user.username });
      await loadUsers();
    } catch (err) {
      console.error("Failed deleting Warpgate user:", err);
      setError(err instanceof Error ? err.message : "Unable to delete this user.");
    }
  }

  async function handleApplicationRoleChange(userId, applicationRole) {
    setUpdatingRoleUserId(userId);
    setError("");
    try {
      const updated = await setWarpgateUserApplicationRole(
        userId,
        applicationRole,
      );
      setUsers((currentUsers) =>
        currentUsers.map((user) =>
          user.id === userId
            ? { ...user, applicationRole: updated.application_role }
            : user,
        ),
      );
      void logSecureAccessEvent("users", "application_role.changed", {
        applicationRole: updated.application_role,
      });
    } catch (err) {
      console.error("Failed to update Secure Access application role:", err);
      setError("Unable to update the application role. SecureAccess rejected the change.");
    } finally {
      setUpdatingRoleUserId("");
    }
  }

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      loadUsers();
    }, 0);
    return () => window.clearTimeout(timeoutId);
  }, [loadUsers]);

  useEffect(() => {
    if (!isAddUserOpen) {
      return undefined;
    }

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        closeAddUser();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isAddUserOpen, closeAddUser]);

  const filteredUsers =
    users.filter((user) => {

      const query =
        search
          .trim()
          .toLowerCase();


      if (!query) {
        return true;
      }


      return (
        user.username
          ?.toLowerCase()
          .includes(query) ||

        user.description
          ?.toLowerCase()
          .includes(query)
      );

    });


  const accessRoleCount =
    new Set(
      users.flatMap(
        (user) =>
          user.accessRoles.map(
            (role) => role.id
          )
      )
    ).size;


  return (
    <DashboardLayout>

      {/* PAGE HEADER */}

      <div className="users-page-header">

        <div>

          <h1>
            Users
          </h1>

          <p>
            Manage SecureAccess users,
            access roles and administrative access.
          </p>

        </div>


        <button
          className="add-user-button"
          onClick={() => {
            setIsAddUserOpen(true);
            setUserEditor({ title: "Add User", src: "/@warpgate/admin#/config/users/create" });
            void logSecureAccessEvent("users", "user.create.opened");
          }}
          type="button"
        >

          <Plus size={16} />

          Add User

        </button>

      </div>


      {/* SUMMARY */}

      <div className="users-summary">

        <div className="users-summary-card">

          <span>
            Total Users
          </span>

          <strong>
            {users.length}
          </strong>

        </div>


        <div className="users-summary-card">

          <span>
            Access Roles
          </span>

          <strong>
            {accessRoleCount}
          </strong>

        </div>


        <div className="users-summary-card">

          <span>
            Admin Users
          </span>

          <strong>

            {
              users.filter(
                (user) =>
                  user.applicationRole === "admin"
              ).length
            }

          </strong>

        </div>
      </div>


      {/* MAIN PANEL */}

      <section className="users-panel">


        {/* TOOLBAR */}

        <div className="users-toolbar">

          <div className="users-search">

            <Search size={16} />

            <input
              type="text"
              placeholder="Search users..."
              value={search}
              onChange={(event) =>
                setSearch(
                  event.target.value
                )
              }
            />

          </div>

        </div>


        {/* LOADING */}

        {loading && (

          <div
            style={{
              padding: "30px",
              textAlign: "center",
              fontSize: "11px",
              color: "#667085",
            }}
          >

            Loading SecureAccess users...

          </div>

        )}


        {/* ERROR */}

        {!loading && error && (

          <div
            style={{
              padding: "30px",
              textAlign: "center",
              fontSize: "11px",
              color: "#b42318",
            }}
          >

            {error}

          </div>

        )}


        {/* TABLE */}

        {!loading && !error && (

          <div className="users-table-wrapper">

            <table className="users-table">

              <thead>

                <tr>

                  <th>User</th>

                  <th>Description</th>

                  <th>Access Roles</th>
                  <th>Admin Roles</th>
                  <th>SecureAccess Role</th>
                  <th></th>

                </tr>

              </thead>


              <tbody>

                {filteredUsers.map(
                  (user) => (

                    <tr key={user.id}>


                      {/* USER */}

                      <td>

                        <div className="user-main-cell">

                          <div className="user-table-avatar">

                            {user.username
                              ?.charAt(0)
                              .toUpperCase()}

                          </div>


                          <div>

                            <strong>
                              {user.username}
                            </strong>

                          </div>

                        </div>

                      </td>


                      {/* DESCRIPTION */}

                      <td className="muted-cell">

                        {user.description ||
                          "—"}

                      </td>


                      {/* ACCESS ROLES */}

                      <td>

                        {user.accessRoles.length >
                        0 ? (

                          user.accessRoles
                            .filter(
                              (role) =>
                                role.is_active !==
                                false
                            )
                            .map(
                              (role) => (

                                <span
                                  className="role-badge"
                                  key={role.id}
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

                          <span className="muted-cell">
                            —
                          </span>

                        )}

                      </td>


                      {/* ADMIN ROLES */}

                      <td>

                        {user.adminRoles.length >
                        0 ? (

                          user.adminRoles.map(
                            (role) => (

                              <span
                                className="role-badge"
                                key={role.id}
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

                          <span className="muted-cell">
                            —
                          </span>

                        )}

                      </td>


                      {/* APPLICATION ROLE */}

                      <td>
                        <select
                          aria-label={`SecureAccess role for ${user.username}`}
                          disabled={
                            updatingRoleUserId === user.id ||
                            user.applicationRole === "admin"
                          }
                          onChange={(event) =>
                            void handleApplicationRoleChange(
                              user.id,
                              event.target.value,
                            )
                          }
                          value={user.applicationRole}
                        >
                          {user.applicationRole === "admin" && (
                            <option value="admin">Admin (SecureAccess)</option>
                          )}
                          <option value="developer">Developer</option>
                          <option value="auditor_viewer">Auditor/Viewer</option>
                        </select>
                      </td>

                      {/* ACTIONS */}

                      <td className="user-actions-cell">

                        <RowActionsMenu
                          label={user.username}
                          onDelete={() => void handleDeleteUser(user)}
                          onEdit={() => {
                            setUserEditor({
                              title: `Edit ${user.username}`,
                              src: `/@warpgate/admin#/config/users/${encodeURIComponent(user.id)}`,
                            });
                            setIsAddUserOpen(true);
                          }}
                        />

                      </td>

                    </tr>

                  )
                )}


                {filteredUsers.length ===
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

                      No users found.

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        )}


        {/* FOOTER */}

        {!loading && !error && (

          <div className="users-footer">

            <span>

              Showing{" "}
              {filteredUsers.length} of{" "}
              {users.length} users

            </span>


            <button
              onClick={loadUsers}
            >

              Refresh

            </button>

          </div>

        )}

      </section>

      {isAddUserOpen && (
        <div
          className="warpgate-user-modal-backdrop"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              closeAddUser();
            }
          }}
        >
          <section
            aria-label="Add user with SecureAccess"
            aria-modal="true"
            className="warpgate-user-modal"
            role="dialog"
          >
            <div className="warpgate-user-modal-header">
              <h2>{userEditor?.title || "Add User"}</h2>
              <button
                aria-label="Close Add User"
                className="warpgate-user-modal-close"
                onClick={closeAddUser}
                type="button"
              >
                ×
              </button>
            </div>
            <WarpgateAdminFrame
              className="warpgate-user-modal-frame"
              src={userEditor?.src || "/@warpgate/admin#/config/users/create"}
              title="SecureAccess user configuration"
            />
          </section>
        </div>
      )}

    </DashboardLayout>
  );
}

export default UsersPage;