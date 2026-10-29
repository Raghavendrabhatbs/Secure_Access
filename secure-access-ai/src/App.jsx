import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import { logSecureAccessEvent } from "./api/audit";
import { AppRoleProvider } from "./auth/AppRoleProvider";
import AppRoutes from "./routes/AppRoutes";

function App() {
  const location = useLocation();
  const lastTrackedLocation = useRef("");
  const route = location.pathname;
  const canonicalizeLocalhost = ["127.0.0.1", "::1", "[::1]"].includes(
    window.location.hostname,
  );

  useEffect(() => {
    if (!canonicalizeLocalhost) {
      return;
    }

    const canonicalUrl = new URL(window.location.href);
    canonicalUrl.hostname = "localhost";
    window.location.replace(canonicalUrl.href);
  }, [canonicalizeLocalhost]);

  useEffect(() => {
    if (canonicalizeLocalhost) {
      return;
    }
    if (route === "/" || lastTrackedLocation.current === route) {
      return;
    }
    lastTrackedLocation.current = route;
    void logSecureAccessEvent("navigation", "page.viewed", { route });
  }, [route, canonicalizeLocalhost]);

  useEffect(() => {
    if (canonicalizeLocalhost) {
      return;
    }
    function handleClick(event) {
      if (window.location.pathname === "/") {
        return;
      }
      const target = event.target;
      if (!(target instanceof Element)) {
        return;
      }
      const control = target.closest("button, a, [role='button']");
      if (!control) {
        return;
      }

      const label = (
        control.getAttribute("aria-label") ||
        control.title ||
        control.textContent ||
        ""
      )
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 100);

      void logSecureAccessEvent("ui", "control.activated", {
        route: window.location.pathname,
        control: control.tagName.toLowerCase(),
        ...(label ? { label } : {}),
      });
    }

    function handleSubmit(event) {
      if (window.location.pathname === "/") {
        return;
      }
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }

      void logSecureAccessEvent("ui", "form.submitted", {
        route: window.location.pathname,
        form: form.id || form.name || "unnamed",
      });
    }

    function handleChange(event) {
      if (window.location.pathname === "/") {
        return;
      }
      const field = event.target;
      if (
        !(field instanceof HTMLInputElement ||
          field instanceof HTMLSelectElement ||
          field instanceof HTMLTextAreaElement) ||
        (field instanceof HTMLInputElement && field.type === "password")
      ) {
        return;
      }

      void logSecureAccessEvent("ui", "form.field.changed", {
        route: window.location.pathname,
        field: field.id || field.name || "unnamed",
        control: field.tagName.toLowerCase(),
      });
    }

    document.addEventListener("click", handleClick);
    document.addEventListener("submit", handleSubmit);
    document.addEventListener("change", handleChange);
    return () => {
      document.removeEventListener("click", handleClick);
      document.removeEventListener("submit", handleSubmit);
      document.removeEventListener("change", handleChange);
    };
  }, [canonicalizeLocalhost]);

  if (canonicalizeLocalhost) {
    return null;
  }

  return (
    <AppRoleProvider>
      <AppRoutes />
    </AppRoleProvider>
  );
}

export default App;