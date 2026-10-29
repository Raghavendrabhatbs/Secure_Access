import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { getWarpgateInfo } from "../api/warpgate";
import { AppRoleContext } from "./AppRoleContext";

export function AppRoleProvider({ children }) {
  const location = useLocation();
  const [state, setState] = useState({ role: null, pathname: null });
  const pathname = location.pathname;

  useEffect(() => {
    if (pathname === "/") {
      return undefined;
    }
    let current = true;
    getWarpgateInfo()
      .then((info) => {
        if (!current) {
          return;
        }
        const requestedRole = info.application_role;
        setState({
          role: ["admin", "developer", "auditor_viewer"].includes(requestedRole)
            ? requestedRole
            : null,
          pathname,
        });
      })
      .catch((error) => {
        console.error("Unable to load the current application role:", error);
        if (current) {
          setState({ role: null, pathname });
        }
      });

    return () => {
      current = false;
    };
  }, [pathname]);

  const loading = pathname !== "/" && state.pathname !== pathname;
  return (
    <AppRoleContext.Provider
      value={{ role: loading ? null : state.role, loading }}
    >
      {children}
    </AppRoleContext.Provider>
  );
}
