import React from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import { AppStateProvider } from "./state/AppState";
import { ThemeProvider } from "./theme/ThemeProvider";

// Locally bundled Poppins (latin subset, weights 400/500/600/700) via
// @fontsource/poppins. The WOFF2 assets are compiled into the app by Vite,
// so the desktop app ships its own font files and makes NO runtime web/font
// request. Only the weights/styles actually used are imported. The system
// fallback stack in --font-family remains for environments without the
// bundled assets.
import "@fontsource/poppins/latin-400.css";
import "@fontsource/poppins/latin-500.css";
import "@fontsource/poppins/latin-600.css";
import "@fontsource/poppins/latin-700.css";

import "./styles/global.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("root container missing");
}

createRoot(container).render(
  <React.StrictMode>
    <ThemeProvider>
      <AppStateProvider>
        <App />
      </AppStateProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
