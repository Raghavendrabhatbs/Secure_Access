import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({

  build: {
    outDir: "../server/public",

    emptyOutDir: false,

    lib: {
      entry: resolve(
        __dirname,
        "src/recorder.js"
      ),

      name: "RRWebRecorder",

      formats: ["iife"],

      fileName: () =>
        "rrweb-recorder.js",
    },
  },


  server: {

    port: 5173,

    host: "127.0.0.1",


    proxy: {
      "/@warpgate/api": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
      },
      "/@warpgate/rrweb": {
        target: "https://localhost:8888",
        changeOrigin: true,
        secure: false,
      },
    },

  },

});