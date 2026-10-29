(function () {
  "use strict";

  const script = document.currentScript;
  const token = script?.dataset.recordingToken;
  const sessionId = script?.dataset.recordingSessionId;
  if (
    !token ||
    typeof sessionId !== "string" ||
    !/^session-[A-Za-z0-9_-]+$/.test(sessionId)
  ) {
    console.error("Web recording disconnect control is missing session credentials.");
    return;
  }

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Disconnect";
  button.setAttribute(
    "aria-label",
    "Disconnect from this web target and stop its recording",
  );
  Object.assign(button.style, {
    position: "fixed",
    top: "12px",
    right: "12px",
    zIndex: "2147483647",
    padding: "8px 14px",
    border: "1px solid #dc2626",
    borderRadius: "6px",
    background: "#b91c1c",
    color: "#ffffff",
    font: "600 13px/1.3 system-ui, sans-serif",
    boxShadow: "0 2px 10px rgba(0, 0, 0, 0.24)",
    cursor: "pointer",
  });

  const errorMessage = document.createElement("span");
  errorMessage.setAttribute("role", "alert");
  Object.assign(errorMessage.style, {
    position: "fixed",
    top: "54px",
    right: "12px",
    zIndex: "2147483647",
    maxWidth: "min(360px, calc(100vw - 24px))",
    padding: "8px 10px",
    border: "1px solid #fecaca",
    borderRadius: "6px",
    background: "#fff1f2",
    color: "#991b1b",
    font: "13px/1.4 system-ui, sans-serif",
    boxShadow: "0 2px 10px rgba(0, 0, 0, 0.18)",
    display: "none",
  });

  button.addEventListener("click", async function () {
    if (
      !window.confirm(
        "Disconnect from this web target and stop its recording?",
      )
    ) {
      return;
    }

    button.disabled = true;
    button.textContent = "Disconnecting...";
    errorMessage.style.display = "none";

    try {
      const stopEvent = new CustomEvent("warpgate-rrweb-stop-request", {
        detail: {},
      });
      window.dispatchEvent(stopEvent);
      if (stopEvent.detail.stopPromise) {
        await stopEvent.detail.stopPromise;
      } else {
        window.dispatchEvent(new Event("pagehide"));
        const pendingKey = `rrweb-pending-batches:${sessionId}`;
        const flushDeadline = Date.now() + 10_000;
        let eventsFlushed = false;
        while (!eventsFlushed && Date.now() < flushDeadline) {
          const pendingBatches = JSON.parse(
            sessionStorage.getItem(pendingKey) || "[]",
          );
          if (!Array.isArray(pendingBatches)) {
            throw new Error("The pending recording queue is invalid.");
          }
          if (pendingBatches.length === 0) {
            eventsFlushed = true;
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        if (!eventsFlushed) {
          throw new Error(
            "Recording events are still uploading. Keep this page open and retry.",
          );
        }

        const response = await fetch(
          `/@warpgate/rrweb/api/sessions/${encodeURIComponent(sessionId)}/stop`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${token}` },
          },
        );
        if (!response.ok) {
          let serverMessage = "";
          try {
            const body = await response.json();
            serverMessage = typeof body.error === "string" ? body.error : "";
          } catch {
            // The response status still provides an actionable failure.
          }
          throw new Error(
            serverMessage || `Disconnect failed with HTTP ${response.status}.`,
          );
        }
      }

      window.close();
      window.setTimeout(function () {
        if (window.closed) {
          return;
        }
        button.disabled = true;
        button.textContent = "Recording stopped";
        errorMessage.textContent =
          "The web session and recording have ended. Close this tab to return to SecureAccess.";
        errorMessage.style.display = "block";
      }, 100);
    } catch (error) {
      console.error("Unable to stop the Web recording:", error);
      errorMessage.textContent =
        error instanceof Error
          ? `${error.message} Please retry disconnecting.`
          : "Unable to stop the recording. Please retry disconnecting.";
      errorMessage.style.display = "block";
      button.disabled = false;
      button.textContent = "Disconnect";
    }
  });

  document.documentElement.append(button, errorMessage);
})();
