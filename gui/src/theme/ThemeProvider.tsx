import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type ThemeMode = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

interface ThemeContextValue {
  /** The user's selected mode: automatic OS detection or a manual override. */
  mode: ThemeMode;
  /** The theme actually applied after resolving `system`. */
  resolved: ResolvedTheme;
  setMode: (mode: ThemeMode) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

const STORAGE_KEY = "tari-private-ballot.theme";

function systemTheme(): ResolvedTheme {
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return "light";
}

function readStoredMode(): ThemeMode {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
  } catch {
    /* storage unavailable: fall through to automatic detection */
  }
  return "system";
}

/**
 * Theme resolution: automatic OS detection (`prefers-color-scheme`) with a
 * manual override persisted in localStorage. The resolved theme is applied
 * as `data-theme` on the document root; all colors come from the token
 * scales in global.css.
 *
 * The NATIVE window chrome (Windows title bar, macOS window appearance) is
 * kept in the SAME theme through Tauri's supported `Window::set_theme` API:
 * dark app theme -> dark title bar, light app theme -> light title bar. In
 * `system` mode the override is cleared (`setTheme(null)`) so the OS decides,
 * exactly like the web content does via `prefers-color-scheme`. This uses a
 * public cross-platform Tauri API — no frameless title bar and no Windows-only
 * hacks — and silently no-ops outside the desktop shell (plain browser dev).
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(readStoredMode);
  const [resolved, setResolved] = useState<ResolvedTheme>(() =>
    mode === "system" ? systemTheme() : mode,
  );

  useEffect(() => {
    if (mode !== "system") {
      setResolved(mode);
      return;
    }
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => setResolved(query.matches ? "dark" : "light");
    apply();
    query.addEventListener("change", apply);
    return () => query.removeEventListener("change", apply);
  }, [mode]);

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  // Native window theme follows the RESOLVED theme; `system` clears the
  // override so the native chrome tracks the OS like the content does.
  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return;
    void import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) =>
        getCurrentWindow().setTheme(mode === "system" ? null : resolved),
      )
      .catch(() => {
        /* older shells or denied permission: web theme still applies */
      });
  }, [mode, resolved]);

  const setMode = useCallback((next: ThemeMode) => {
    setModeState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* storage unavailable: the override lasts for this session only */
    }
  }, []);

  const value = useMemo(() => ({ mode, resolved, setMode }), [mode, resolved, setMode]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
