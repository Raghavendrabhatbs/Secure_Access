import { record } from "@rrweb/record";
import {
  gatewayUrl as createGatewayUrl,
  isGatewayRoutedUrl,
  navigationOriginFor,
  originMatchesScope,
} from "./navigation.mjs";

const RRWEB_API_BASE_URL = "/@warpgate/rrweb";
const TARGETS_API_URL = "/@warpgate/api/targets";
const TOKEN_API_URL = "/@warpgate/api/rrweb-recording-token";
const RECORDER_FLAG = "__warpgateRrwebRecorderInstalled";
const RECORDING_CONTEXT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECORDING_CONTEXT_CHANNEL = "warpgate-rrweb-recording-context";

function createId() {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function httpError(message, status) {
  const error = new Error(message);
  error.httpStatus = status;
  return error;
}

function initializeRecorder() {
  const script = document.currentScript;
  let recordingToken = null;
  const warpgateUsername = script?.dataset?.warpgateUsername || "unknown";
  const authenticationType =
    script?.dataset?.warpgateAuthenticationType || "unknown";
  const warpgateTarget = script?.dataset?.warpgateTarget || "unknown";
  const warpgateSessionId = script?.dataset?.warpgateSessionId || "";
  const upstreamUrl = script?.dataset?.upstreamUrl || window.location.href;
  const configuredTargetOrigin =
    script?.dataset?.targetOrigin || upstreamUrl;

  let sessionId = null;
  let outboxKey = null;
  let tokenExpiresAt = 0;
  let pendingBatches = [];
  let eventBuffer = [];
  let sessionReady = false;
  let recorderStarted = false;
  let uploadInProgress = false;
  let sessionStartInProgress = false;
  let startRetryDelay = 1000;
  let tokenRefreshInProgress = false;
  let stopRecorder = null;
  let authorizedTargets = [];
  let lastVisitedUrl = null;
  let visitRetryTimer = null;

  let recordingContextId;
  let contextChannel = null;
  let contextClaimed = false;
  try {
    const previousTarget = sessionStorage.getItem("rrweb-active-target");
    const previousUsername = sessionStorage.getItem("rrweb-active-username");
    const previousWarpgateSessionId = sessionStorage.getItem(
      "rrweb-active-warpgate-session-id",
    );
    recordingContextId = sessionStorage.getItem("rrweb-recording-context-id");
    if (
      previousTarget !== warpgateTarget ||
      previousUsername !== warpgateUsername ||
      previousWarpgateSessionId !== warpgateSessionId ||
      !RECORDING_CONTEXT_ID_PATTERN.test(recordingContextId || "")
    ) {
      recordingContextId = createId();
      sessionStorage.setItem("rrweb-active-target", warpgateTarget);
      sessionStorage.setItem("rrweb-active-username", warpgateUsername);
      sessionStorage.setItem(
        "rrweb-active-warpgate-session-id",
        warpgateSessionId,
      );
      sessionStorage.setItem(
        "rrweb-recording-context-id",
        recordingContextId,
      );
    }
  } catch (error) {
    console.error("Unable to persist the rrweb tab context:", error);
    recordingContextId = createId();
  }

  async function claimUniqueTabContext() {
    if (typeof BroadcastChannel !== "function") {
      throw new Error("This browser cannot isolate recording contexts across tabs.");
    }

    contextChannel = new BroadcastChannel(RECORDING_CONTEXT_CHANNEL);
    const tabInstanceId = createId();
    let duplicateContext = false;

    contextChannel.addEventListener("message", ({ data }) => {
      if (
        !data ||
        data.contextId !== recordingContextId ||
        data.tabInstanceId === tabInstanceId
      ) {
        return;
      }

      if (data.type === "probe") {
        contextChannel.postMessage({
          type: "probe-response",
          active: contextClaimed,
          contextId: recordingContextId,
          tabInstanceId,
        });
      } else if (
        data.type === "active" ||
        (data.type === "probe-response" &&
          (data.active ||
            (!contextClaimed && tabInstanceId > data.tabInstanceId)))
      ) {
        duplicateContext = true;
      }
    });

    contextChannel.postMessage({
      type: "probe",
      contextId: recordingContextId,
      tabInstanceId,
    });
    await new Promise((resolve) => setTimeout(resolve, 100));

    if (duplicateContext) {
      recordingContextId = createId();
      sessionStorage.setItem("rrweb-recording-context-id", recordingContextId);
    }

    contextClaimed = true;
    contextChannel.postMessage({
      type: "active",
      contextId: recordingContextId,
      tabInstanceId,
    });
    window.addEventListener(
      "pagehide",
      () => contextChannel?.close(),
      { once: true },
    );
  }

  function restoreOutbox() {
    outboxKey = `rrweb-pending-batches:${sessionId}`;
    try {
      const storedBatches = JSON.parse(
        sessionStorage.getItem(outboxKey) || "[]",
      );
      if (Array.isArray(storedBatches)) {
        pendingBatches = storedBatches.filter(
          (batch) =>
            batch &&
            typeof batch.batchId === "string" &&
            Array.isArray(batch.events),
        );
      }
    } catch (error) {
      console.error("Unable to restore pending rrweb event batches:", error);
    }
  }

  function persistOutbox() {
    if (!outboxKey) {
      return;
    }
    try {
      sessionStorage.setItem(outboxKey, JSON.stringify(pendingBatches));
    } catch (error) {
      console.error(
        "Unable to persist pending rrweb events; they remain queued in memory:",
        error,
      );
    }
  }

  function startRecorder() {
    if (recorderStarted) {
      return;
    }
    recorderStarted = true;
    stopRecorder = record({
      maskAllInputs: true,
      emit(event) {
        eventBuffer.push(event);
      },
    });
  }

  function enqueueBufferedEvents() {
    if (eventBuffer.length === 0) {
      return;
    }
    pendingBatches.push({
      batchId: createId(),
      events: eventBuffer,
    });
    eventBuffer = [];
    persistOutbox();
  }

  async function refreshToken(force = false) {
    if (
      tokenRefreshInProgress ||
      (!force && tokenExpiresAt > Date.now() + 60_000)
    ) {
      return recordingToken;
    }

    tokenRefreshInProgress = true;
    try {
      const response = await fetch(TOKEN_API_URL, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_name: warpgateTarget,
          recording_context_id: recordingContextId,
        }),
      });
      if (!response.ok) {
        throw httpError(
          `Warpgate token refresh failed: ${response.status}`,
          response.status,
        );
      }
      const result = await response.json();
      if (
        typeof result.token !== "string" ||
        !Number.isFinite(result.expires_at) ||
        typeof result.recording_session_id !== "string" ||
        !/^session-[A-Za-z0-9_-]+$/.test(result.recording_session_id) ||
        (sessionId && result.recording_session_id !== sessionId)
      ) {
        throw new Error("Warpgate returned an invalid recording token");
      }
      if (!sessionId) {
        sessionId = result.recording_session_id;
        restoreOutbox();
      }
      recordingToken = result.token;
      tokenExpiresAt = result.expires_at;
      return recordingToken;
    } catch (error) {
      console.error("Unable to refresh the rrweb recording token:", error);
      void reportRecordingFailure(
        "token",
        recordingToken,
        error.httpStatus,
      );
      return null;
    } finally {
      tokenRefreshInProgress = false;
    }
  }

  async function reportRecordingFailure(stage, token, status) {
    if (!token || tokenExpiresAt <= Date.now()) {
      return;
    }
    try {
      const response = await fetch(
        `${RRWEB_API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/failures`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ stage, httpStatus: status ?? null }),
          credentials: "same-origin",
        },
      );
      if (!response.ok) {
        console.warn(
          `Unable to report rrweb ${stage} failure: HTTP ${response.status}`,
        );
      }
    } catch (error) {
      console.warn(`Unable to report rrweb ${stage} failure:`, error);
    }
  }

  async function uploadPendingBatches(keepalive = false) {
    if (!sessionReady || uploadInProgress) {
      return;
    }
    enqueueBufferedEvents();
    if (pendingBatches.length === 0) {
      return;
    }

    let token = null;
    token = keepalive
      ? tokenExpiresAt > Date.now()
        ? recordingToken
        : null
      : await refreshToken();
    if (!token) {
      return;
    }

    uploadInProgress = true;
    try {
      while (pendingBatches.length > 0) {
        const batch = pendingBatches[0];
        const response = await fetch(
          `${RRWEB_API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/events`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(batch),
            keepalive,
            credentials: "same-origin",
          },
        );
        if (!response.ok) {
          throw httpError(
            `Event upload failed: ${response.status}`,
            response.status,
          );
        }
        pendingBatches.shift();
        persistOutbox();
      }
    } catch (error) {
      console.error("RRWeb event batch remains queued for retry:", error);
      void reportRecordingFailure("upload", token, error.httpStatus);
    } finally {
      uploadInProgress = false;
    }
  }

  async function registerPageVisit(
    navigationType,
    visit = {
      visitId: createId(),
      pageUrl: currentUpstreamPageUrl(),
      pageTitle: document.title,
      referrer: document.referrer,
    },
  ) {
    if (!sessionReady || !recordingToken) {
      return;
    }
    const { visitId, pageUrl, pageTitle, referrer } = visit;
    if (pageUrl === lastVisitedUrl) {
      return;
    }
    lastVisitedUrl = pageUrl;
    try {
      const token = await refreshToken();
      if (!token) {
        throw new Error("No valid rrweb recording token is available");
      }
      const response = await fetch(`${RRWEB_API_BASE_URL}/api/sessions/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          sessionId,
          visitId,
          username: warpgateUsername,
          authenticationType,
          target: warpgateTarget,
          pageUrl,
          pageTitle,
          referrer,
          navigationType,
        }),
        credentials: "same-origin",
      });
      if (!response.ok) {
        throw httpError(
          `Page visit registration failed: ${response.status}`,
          response.status,
        );
      }
    } catch (error) {
      lastVisitedUrl = null;
      console.error("Unable to register rrweb page visit:", error);
      void reportRecordingFailure(
        "start",
        recordingToken,
        error.httpStatus,
      );
      clearTimeout(visitRetryTimer);
      visitRetryTimer = setTimeout(
        () => registerPageVisit(navigationType, visit),
        2000,
      );
    }
  }

  async function startSession(
    initialVisit = {
      visitId: createId(),
      pageUrl: currentUpstreamPageUrl(),
      pageTitle: document.title,
      referrer: document.referrer,
      navigationType:
        performance.getEntriesByType("navigation")[0]?.type || "unknown",
    },
  ) {
    if (sessionStartInProgress || sessionReady) {
      return;
    }
    sessionStartInProgress = true;
    try {
      if (!await refreshToken(true)) {
        throw new Error("No valid rrweb recording token is available");
      }
      const response = await fetch(`${RRWEB_API_BASE_URL}/api/sessions/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${recordingToken}`,
        },
        body: JSON.stringify({
          sessionId,
          visitId: initialVisit.visitId,
          username: warpgateUsername,
          authenticationType,
          target: warpgateTarget,
          pageUrl: initialVisit.pageUrl,
          pageTitle: initialVisit.pageTitle,
          referrer: initialVisit.referrer,
          navigationType: initialVisit.navigationType,
        }),
        credentials: "same-origin",
      });
      if (!response.ok) {
        throw httpError(
          `Session start failed: ${response.status}`,
          response.status,
        );
      }
      sessionReady = true;
      lastVisitedUrl = initialVisit.pageUrl;
      startRetryDelay = 1000;
      startRecorder();
      await uploadPendingBatches();
    } catch (error) {
      console.error("Unable to start/resume rrweb session:", error);
      void reportRecordingFailure(
        "start",
        recordingToken,
        error.httpStatus,
      );
      clearTimeout(visitRetryTimer);
      visitRetryTimer = setTimeout(
        () => startSession(initialVisit),
        startRetryDelay,
      );
      startRetryDelay = Math.min(startRetryDelay * 2, 30_000);
    } finally {
      sessionStartInProgress = false;
    }
  }

  async function stopRecordingSession() {
    if (!sessionReady || !sessionId) {
      throw new Error("This Web recording is not active.");
    }

    stopRecorder?.();
    stopRecorder = null;
    enqueueBufferedEvents();
    await uploadPendingBatches();
    if (pendingBatches.length > 0) {
      throw new Error("Recording events are still uploading. Please retry.");
    }

    const token = await refreshToken(true);
    if (!token) {
      throw new Error("Unable to refresh recording authorization.");
    }
    const response = await fetch(
      `${RRWEB_API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/stop`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        credentials: "same-origin",
      },
    );
    if (!response.ok) {
      throw httpError(`Recording stop failed: ${response.status}`, response.status);
    }
    sessionReady = false;
  }

  window.addEventListener("warpgate-rrweb-stop-request", (event) => {
    if (event.detail && typeof event.detail === "object") {
      event.detail.stopPromise = stopRecordingSession();
    }
  });

  async function loadAuthorizedTargets() {
    try {
      const response = await fetch(TARGETS_API_URL, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Authorized target lookup failed: ${response.status}`);
      }
      const targets = await response.json();
      authorizedTargets = targets
        .filter(
          (target) =>
            String(target.kind).toLowerCase() === "http" &&
            typeof target.http_origin === "string",
        )
        .map((target) => ({
          name: target.name,
          origin: target.http_origin,
          navigationOrigin:
            target.http_navigation_origin || target.http_origin,
        }));
    } catch (error) {
      console.error("Unable to load authorized Warpgate HTTP targets:", error);
    }
  }

  let initialPage;
  try {
    initialPage = new URL(upstreamUrl);
  } catch {
    console.error("Invalid upstream URL; navigation rewriting is disabled");
    initialPage = new URL(window.location.href);
  }

  let configuredOrigin;
  try {
    configuredOrigin = new URL(configuredTargetOrigin).origin;
  } catch {
    console.error("Invalid configured target origin; navigation rewriting is disabled");
    configuredOrigin = initialPage.origin;
  }
  const currentTargetRoute = {
    name: warpgateTarget,
    origin: configuredOrigin,
    navigationOrigin: navigationOriginFor(configuredOrigin),
  };

  function targetForDestination(destination) {
    return (
      (originMatchesScope(destination, currentTargetRoute) &&
        currentTargetRoute) ||
      authorizedTargets.find((target) => originMatchesScope(destination, target))
    );
  }

  function gatewayUrl(destination, target) {
    return createGatewayUrl(destination, target, window.location.origin);
  }

  function resolveDestination(value) {
    try {
      return new URL(value, currentUpstreamPageUrl());
    } catch {
      return null;
    }
  }

  function isWarpgateRoutedUrl(value) {
    return isGatewayRoutedUrl(value, window.location.origin);
  }

  function currentUpstreamPageUrl() {
    const current = new URL(window.location.href);
    current.searchParams.delete("warpgate-target");
    current.searchParams.delete("warpgate-ticket");
    current.searchParams.delete("warpgate-host");
    return new URL(
      `${current.pathname}${current.search}${current.hash}`,
      initialPage.origin,
    ).href;
  }

  function showBlockedNavigation() {
    console.warn(
      "Navigation blocked: destination is not an authorized Warpgate HTTP target",
    );
    let message = document.getElementById("warpgate-navigation-blocked");
    if (!message) {
      message = document.createElement("div");
      message.id = "warpgate-navigation-blocked";
      message.setAttribute("role", "alert");
      message.style.cssText =
        "position:fixed;z-index:2147483647;left:1rem;bottom:1rem;padding:.75rem 1rem;background:#7f1d1d;color:white;border-radius:.5rem;font:14px sans-serif";
      document.body.append(message);
    }
    message.textContent =
      "Navigation blocked: this destination is not an authorized Warpgate HTTP target.";
    setTimeout(() => message.remove(), 6000);
  }

  function rewriteLink(anchor) {
    const rawHref = anchor.getAttribute("href");
    if (
      !rawHref ||
      /^(#|javascript:|mailto:|tel:|data:|blob:)/i.test(rawHref) ||
      rawHref.startsWith("/@warpgate") ||
      isWarpgateRoutedUrl(rawHref)
    ) {
      return;
    }
    const destination = resolveDestination(rawHref);
    if (!destination || !/^https?:$/.test(destination.protocol)) {
      return;
    }
    const target = targetForDestination(destination);
    if (target) {
      anchor.setAttribute("href", gatewayUrl(destination, target));
    }
  }

  function rewriteLinks(root) {
    if (root instanceof HTMLAnchorElement) {
      rewriteLink(root);
    }
    root.querySelectorAll?.("a[href]").forEach(rewriteLink);
  }

  function navigationTypeForHistory(kind) {
    return `spa-${kind}`;
  }

  function trackSpaVisit(kind) {
    queueMicrotask(() => registerPageVisit(navigationTypeForHistory(kind)));
  }

  const originalPushState = history.pushState.bind(history);
  history.pushState = function (...args) {
    const result = originalPushState(...args);
    trackSpaVisit("push");
    return result;
  };
  const originalReplaceState = history.replaceState.bind(history);
  history.replaceState = function (...args) {
    const result = originalReplaceState(...args);
    trackSpaVisit("replace");
    return result;
  };
  window.addEventListener("popstate", () => registerPageVisit("back-forward"));
  window.addEventListener("hashchange", () => registerPageVisit("hash"));

  rewriteLinks(document);
  const linkObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (
        mutation.type === "attributes" &&
        mutation.target instanceof HTMLAnchorElement
      ) {
        rewriteLink(mutation.target);
      }
      for (const node of mutation.addedNodes) {
        if (node instanceof Element) {
          rewriteLinks(node);
        }
      }
    }
  });
  linkObserver.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["href"],
  });

  document.addEventListener(
    "click",
    async (event) => {
      const anchor =
        event.target instanceof Element
          ? event.target.closest("a[href]")
          : null;
      if (!anchor || event.defaultPrevented) {
        return;
      }
      const rawHref = anchor.getAttribute("href");
      if (
        !rawHref ||
        /^(#|javascript:|mailto:|tel:|data:|blob:)/i.test(rawHref) ||
        rawHref.startsWith("/@warpgate")
        || isWarpgateRoutedUrl(rawHref)
      ) {
        return;
      }
      const destination = resolveDestination(rawHref);
      if (!destination || !/^https?:$/.test(destination.protocol)) {
        return;
      }
      const target = targetForDestination(destination);
      if (target) {
        anchor.setAttribute("href", gatewayUrl(destination, target));
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      await loadAuthorizedTargets();
      const authorizedTarget = targetForDestination(destination);
      if (authorizedTarget) {
        window.location.assign(gatewayUrl(destination, authorizedTarget));
      } else {
        showBlockedNavigation();
      }
    },
    true,
  );

  document.addEventListener(
    "submit",
    async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      const rawAction = form.getAttribute("action");
      if (rawAction && isWarpgateRoutedUrl(rawAction)) {
        return;
      }
      const destination = resolveDestination(
        rawAction || currentUpstreamPageUrl(),
      );
      if (!destination || !/^https?:$/.test(destination.protocol)) {
        event.preventDefault();
        showBlockedNavigation();
        return;
      }
      let target = targetForDestination(destination);
      if (!target) {
        event.preventDefault();
        event.stopImmediatePropagation();
        await loadAuthorizedTargets();
        target = targetForDestination(destination);
        if (!target) {
          showBlockedNavigation();
          return;
        }
      }
      form.action = gatewayUrl(destination, target);
    },
    true,
  );

  const originalWindowOpen = window.open.bind(window);
  window.open = function (url, target, features) {
    if (isWarpgateRoutedUrl(String(url || ""))) {
      return originalWindowOpen(url, target, features);
    }
    const destination = resolveDestination(String(url || ""));
    if (!destination || !/^https?:$/.test(destination.protocol)) {
      return originalWindowOpen(url, target, features);
    }
    const targetRoute = targetForDestination(destination);
    const newWindow = originalWindowOpen("about:blank", target, features);
    if (!newWindow) {
      return null;
    }
    if (targetRoute) {
      newWindow.location = gatewayUrl(destination, targetRoute);
    } else {
      loadAuthorizedTargets().then(() => {
        const authorizedTarget = targetForDestination(destination);
        if (authorizedTarget) {
          newWindow.location = gatewayUrl(destination, authorizedTarget);
        } else {
          newWindow.close();
          showBlockedNavigation();
        }
      });
    }
    return newWindow;
  };

  void claimUniqueTabContext()
    .then(() => {
      startRecorder();
      return startSession();
    })
    .catch((error) => {
      console.error("Unable to establish an isolated rrweb recording context:", error);
    });
  loadAuthorizedTargets().then(() => rewriteLinks(document));

  const flushTimer = setInterval(() => uploadPendingBatches(), 2000);
  setInterval(() => refreshToken(true), 3 * 60 * 1000);
  const heartbeatTimer = setInterval(async () => {
    if (!sessionReady) {
      return;
    }
    const token = await refreshToken();
    if (!token) {
      return;
    }
    try {
      const response = await fetch(
        `${RRWEB_API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/heartbeat`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          credentials: "same-origin",
        },
      );
      if (!response.ok) {
        throw httpError(`Recording heartbeat failed: ${response.status}`, response.status);
      }
    } catch (error) {
      console.error("Unable to heartbeat rrweb session:", error);
      void reportRecordingFailure(
        "heartbeat",
        token,
        error.httpStatus,
      );
    }
  }, 30_000);
  window.addEventListener("pagehide", () => {
    clearInterval(flushTimer);
    clearInterval(heartbeatTimer);
    enqueueBufferedEvents();
    void uploadPendingBatches(true);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      void uploadPendingBatches(true);
    }
  });
}

if (!window[RECORDER_FLAG]) {
  window[RECORDER_FLAG] = true;
  initializeRecorder();
}
