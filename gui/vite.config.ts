import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri desktop shell frontend (ADR-0007: Tauri 2 + React + TypeScript + Vite).
// The app is loaded from disk in the system WebView; no remote origins.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: "es2022",
    // CSS minification stays off in this slice: Vite's `cssMinify: true`
    // path loads the lightningcss native binding, whose win32-x64 build for
    // the required version is not in the offline package cache. CSS is small
    // and served from disk; minification is cosmetic here.
    cssMinify: false,
  },
});
