import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8788",
      "/health": "http://127.0.0.1:8788",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      input: {
        main: "index.html",
        guide: "guide.html",
        vote: "vote.html",
        enroll: "enroll.html",
        create: "create.html",
        manage: "manage.html",
        about: "about.html",
        settings: "settings.html",
        archive: "archive.html",
        evidence: "evidence.html",
        anchor: "anchor.html",
      },
    },
  },
});
