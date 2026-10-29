import assert from "node:assert/strict";
import test from "node:test";

import { resolveAiApiTarget } from "./vite.config.js";

const wslRouteTable = [
  "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT",
  "eth0 00000000 017019AC 0003 0 0 0 00000000 0 0 0",
].join("\n");

test("routes WSL requests through the Windows default gateway", () => {
  assert.equal(
    resolveAiApiTarget({
      platform: "linux",
      wslDistroName: "Ubuntu",
      routeTable: wslRouteTable,
    }),
    "http://172.25.112.1:8765",
  );
});

test("uses localhost for Windows development", () => {
  assert.equal(
    resolveAiApiTarget({ platform: "win32", wslDistroName: "", routeTable: wslRouteTable }),
    "http://127.0.0.1:8765",
  );
});

test("routes WSL Groq requests through the Windows default gateway", () => {
  assert.equal(
    resolveAiApiTarget({
      platform: "linux",
      wslDistroName: "Ubuntu",
      routeTable: wslRouteTable,
      port: 8890,
    }),
    "http://172.25.112.1:8890",
  );
});

test("routes Windows Vite requests to the WSL host gateway when available", () => {
  assert.equal(
    resolveAiApiTarget({
      platform: "win32",
      wslDistroName: "",
      routeTable: wslRouteTable,
      port: 8890,
      wslHostGateway: true,
      interfaces: {
        "vEthernet (WSL)": [
          { address: "172.25.112.1", family: "IPv4", internal: false },
        ],
      },
    }),
    "http://172.25.112.1:8890",
  );
});

test("falls back to localhost if the Windows WSL gateway is unavailable", () => {
  assert.equal(
    resolveAiApiTarget({
      platform: "win32",
      wslDistroName: "",
      port: 8890,
      wslHostGateway: true,
      interfaces: {},
    }),
    "http://127.0.0.1:8890",
  );
});

test("respects an explicit API target", () => {
  assert.equal(
    resolveAiApiTarget({
      configuredTarget: "http://api.internal:9000",
      platform: "linux",
      wslDistroName: "Ubuntu",
      routeTable: wslRouteTable,
    }),
    "http://api.internal:9000",
  );
});