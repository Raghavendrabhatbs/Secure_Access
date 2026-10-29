import { readFileSync } from "node:fs";
import { networkInterfaces } from "node:os";
import process from "node:process";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export function resolveAiApiTarget({
  configuredTarget = process.env.AI_API_TARGET,
  port = 8765,
  platform = process.platform,
  wslDistroName = process.env.WSL_DISTRO_NAME,
  routeTable,
  wslHostGateway = false,
  interfaces = networkInterfaces(),
} = {}) {
  if (configuredTarget) return configuredTarget;
  if (platform === "win32" && wslHostGateway) {
    const gatewayInterface = Object.entries(interfaces)
      .find(([name]) => /wsl/i.test(name))
      ?.at(1)
      ?.find(({ family, internal }) => family === "IPv4" && !internal);
    if (gatewayInterface?.address) {
      return `http://${gatewayInterface.address}:${port}`;
    }
  }
  if (platform === "linux" && wslDistroName) {
    try {
      const routes = (routeTable ?? readFileSync("/proc/net/route", "utf8"))
        .trim()
        .split(/\r?\n/)
        .slice(1);
      const defaultRoute = routes
        .map((route) => route.trim().split(/\s+/))
        .find(([, destination, gateway, flags]) =>
          destination === "00000000" && (Number.parseInt(flags, 16) & 2) !== 0 && gateway !== "00000000",
        );
      const gateway = defaultRoute?.[2];
      if (/^[0-9a-f]{8}$/i.test(gateway || "")) {
        const address = gateway.match(/../g).reverse().map((octet) => Number.parseInt(octet, 16));
        return `http://${address.join(".")}:${port}`;
      }
    } catch {
      // Fall back to localhost when WSL route information is unavailable.
    }
  }
  return `http://127.0.0.1:${port}`;
}

const aiApiTarget = resolveAiApiTarget();
const groqAiApiTarget = resolveAiApiTarget({
  configuredTarget: process.env.GROQ_AI_API_TARGET,
  port: 8890,
  wslHostGateway: true,
});

export default defineConfig({
  plugins: [react()],

  server: {
    watch: {
      usePolling: true,
      interval: 1000,
    },
    proxy: {
      "/ai-api": {
        target: aiApiTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/ai-api/, ""),
      },
      "/groq-ai-api": {
        target: groqAiApiTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/groq-ai-api/, ""),
      },
      "/warpgate-api": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,

        rewrite: (path) =>
          path.replace(
            /^\/warpgate-api/,
            "/@warpgate/api"
          ),
      },

      "/warpgate-admin-api": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,

        rewrite: (path) =>
          path.replace(
            /^\/warpgate-admin-api/,
            "/@warpgate/admin/api"
          ),
      },

      "/@warpgate/admin": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
        ws: true,
      },

      "/@warpgate/api": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
        ws: true,
      },

      "/@warpgate/assets": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
      },

      "/@warpgate/rrweb": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
      },

      "/@warpgate": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
});
