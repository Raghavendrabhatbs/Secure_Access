import { createContext } from "react";

export const AppRoleContext = createContext({
  role: null,
  loading: true,
});
