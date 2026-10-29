const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(
  path.join(__dirname, "../public/recording-controls.js"),
  "utf8",
);

function createControl({ fetch, pendingBatches = ["[]"], dispatchStop }) {
  const elements = [];
  const calls = [];
  let closeRequested = false;
  let dispatchedPageHide = false;
  const script = {
    dataset: {
      recordingToken: "signed-recording-token",
      recordingSessionId: "session-web_123",
    },
  };
  const document = {
    currentScript: script,
    createElement() {
      return {
        style: {},
        setAttribute() {},
        addEventListener(_event, handler) {
          this.clickHandler = handler;
        },
      };
    },
    documentElement: {
      append(...nodes) {
        elements.push(...nodes);
      },
    },
  };
  const window = {
    confirm: () => true,
    dispatchEvent(event) {
      if (event.type === "pagehide") {
        dispatchedPageHide = true;
      }
      dispatchStop?.(event);
    },
    location: {
      assign(url) {
        throw new Error(`Unexpected navigation to ${url}`);
      },
    },
    closed: false,
    close() {
      closeRequested = true;
      this.closed = true;
    },
    setTimeout(callback) {
      callback();
    },
  };
  const sessionStorage = {
    getItem() {
      return pendingBatches.shift() || "[]";
    },
  };

  vm.runInNewContext(source, {
    CustomEvent: class {
      constructor(type, options) {
        this.type = type;
        this.detail = options.detail;
      }
    },
    Date,
    Error,
    Event,
    JSON,
    console: { error() {} },
    document,
    encodeURIComponent,
    fetch: async (...args) => {
      calls.push(args);
      return fetch(...args);
    },
    sessionStorage,
    setTimeout,
    window,
  });

  return {
    button: elements[0],
    errorMessage: elements[1],
    calls,
    get dispatchedPageHide() {
      return dispatchedPageHide;
    },
    get closeRequested() {
      return closeRequested;
    },
  };
}

test("disconnect flushes queued events, stops the recording, then closes the web session tab", async () => {
  const control = createControl({
    pendingBatches: ['[{"batchId":"pending"}]', "[]"],
    fetch: async () => ({ ok: true, status: 200 }),
  });

  await control.button.clickHandler();

  assert.equal(control.dispatchedPageHide, true);
  assert.equal(control.calls.length, 1);
  assert.equal(
    control.calls[0][0],
    "/@warpgate/rrweb/api/sessions/session-web_123/stop",
  );
  assert.equal(
    control.calls[0][1].headers.Authorization,
    "Bearer signed-recording-token",
  );
  assert.equal(control.closeRequested, true);
  assert.equal(control.errorMessage.style.display, "none");
});

test("disconnect reports stop failures and leaves the recording page open", async () => {
  const control = createControl({
    fetch: async () => ({
      ok: false,
      status: 404,
      json: async () => ({ error: "Session not found" }),
    }),
  });

  await control.button.clickHandler();

  assert.equal(control.closeRequested, false);
  assert.equal(control.button.disabled, false);
  assert.equal(control.button.textContent, "Disconnect");
  assert.equal(control.errorMessage.style.display, "block");
  assert.match(control.errorMessage.textContent, /Session not found/);
});

test("disconnect delegates to the recorder's isolated session context", async () => {
  const control = createControl({
    fetch: async () => {
      throw new Error("The legacy static session must not be used");
    },
    dispatchStop(event) {
      if (event.type === "warpgate-rrweb-stop-request") {
        event.detail.stopPromise = Promise.resolve();
      }
    },
  });

  await control.button.clickHandler();

  assert.equal(control.calls.length, 0);
  assert.equal(control.dispatchedPageHide, false);
  assert.equal(control.closeRequested, true);
});
