import { useContext } from "react";
import { AppRoleContext } from "./AppRoleContext";

export function useAppRole() {
  return useContext(AppRoleContext);
}
