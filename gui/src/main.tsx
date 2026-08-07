import React from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import { AppStateProvider } from "./state/AppState";
import { ThemeProvider } from "./theme/ThemeProvider";
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
