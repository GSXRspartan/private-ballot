import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { api, BackendError, isDesktopShell } from "../api/client";
import type { GuiElectionSummaryV1, GuiTallySummaryV1 } from "../api/types";

export interface RecentAction {
  at: string;
  label: string;
}

export interface AppSettings {
  dataDirectory: string;
  exportDirectory: string;
  devDiagnostics: boolean;
}

interface AppStateValue {
  shellAvailable: boolean;
  election: GuiElectionSummaryV1 | null;
  tally: GuiTallySummaryV1 | null;
  recentActions: RecentAction[];
  settings: AppSettings;
  backendError: string | null;
  setSetting: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
  refreshElection: () => Promise<void>;
  runLifecycle: (action: "open" | "close" | "verify" | "finalize") => Promise<void>;
  loadElection: (manifestPath: string, registryPath: string, optionSetPath: string) => Promise<void>;
  unloadElection: () => Promise<void>;
  recordAction: (label: string) => void;
}

const AppStateContext = createContext<AppStateValue | null>(null);

const SETTINGS_KEY = "tari-private-ballot.settings";

const DEFAULT_SETTINGS: AppSettings = {
  dataDirectory: "",
  exportDirectory: "",
  devDiagnostics: false,
};

function readSettings(): AppSettings {
  try {
    const raw = window.localStorage.getItem(SETTINGS_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<AppSettings>;
      return { ...DEFAULT_SETTINGS, ...parsed };
    }
  } catch {
    /* fall through to defaults */
  }
  return DEFAULT_SETTINGS;
}

/**
 * Application shell state: the active election summary (a real gui-core view
 * model), the latest tally when fetched, a session-scoped recent-action log,
 * and non-secret user settings. No credential material is ever held here.
 */
export function AppStateProvider({ children }: { children: React.ReactNode }) {
  const [shellAvailable] = useState(isDesktopShell);
  const [election, setElection] = useState<GuiElectionSummaryV1 | null>(null);
  const [tally, setTally] = useState<GuiTallySummaryV1 | null>(null);
  const [recentActions, setRecentActions] = useState<RecentAction[]>([]);
  const [settings, setSettings] = useState<AppSettings>(readSettings);
  const [backendError, setBackendError] = useState<string | null>(null);

  const recordAction = useCallback((label: string) => {
    setRecentActions((prev) =>
      [{ at: new Date().toISOString(), label }, ...prev].slice(0, 12),
    );
  }, []);

  const captureError = useCallback((error: unknown) => {
    if (error instanceof BackendError) {
      setBackendError(`${error.payload.code}: ${error.payload.message}`);
    } else {
      setBackendError("unexpected boundary error");
    }
  }, []);

  const refreshElection = useCallback(async () => {
    try {
      const summary = await api.electionSummary();
      setElection(summary);
      setBackendError(null);
    } catch (error) {
      captureError(error);
    }
  }, [captureError]);

  useEffect(() => {
    if (shellAvailable) {
      void refreshElection();
    }
  }, [shellAvailable, refreshElection]);

  const loadElection = useCallback(
    async (manifestPath: string, registryPath: string, optionSetPath: string) => {
      try {
        const summary = await api.loadElection(manifestPath, registryPath, optionSetPath);
        setElection(summary);
        setTally(null);
        setBackendError(null);
        recordAction(`Loaded election ${summary.election_id_text ?? summary.election_id_hex}`);
      } catch (error) {
        captureError(error);
        throw error;
      }
    },
    [captureError, recordAction],
  );

  const unloadElection = useCallback(async () => {
    try {
      await api.unloadElection();
      setElection(null);
      setTally(null);
      setBackendError(null);
      recordAction("Unloaded election session");
    } catch (error) {
      captureError(error);
    }
  }, [captureError, recordAction]);

  const runLifecycle = useCallback(
    async (action: "open" | "close" | "verify" | "finalize") => {
      const labels = {
        open: "Opened voting",
        close: "Closed voting",
        verify: "Marked election verified",
        finalize: "Finalized election",
      } as const;
      try {
        const summary =
          action === "open"
            ? await api.openVoting()
            : action === "close"
              ? await api.closeVoting()
              : action === "verify"
                ? await api.markVerified()
                : await api.finalizeElection();
        setElection(summary);
        setBackendError(null);
        recordAction(labels[action]);
      } catch (error) {
        captureError(error);
      }
    },
    [captureError, recordAction],
  );

  const setSetting = useCallback(
    <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
      setSettings((prev) => {
        const next = { ...prev, [key]: value };
        try {
          window.localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
        } catch {
          /* settings persist only when storage is available */
        }
        return next;
      });
    },
    [],
  );

  const value = useMemo<AppStateValue>(
    () => ({
      shellAvailable,
      election,
      tally,
      recentActions,
      settings,
      backendError,
      setSetting,
      refreshElection,
      runLifecycle,
      loadElection,
      unloadElection,
      recordAction,
    }),
    [
      shellAvailable,
      election,
      tally,
      recentActions,
      settings,
      backendError,
      setSetting,
      refreshElection,
      runLifecycle,
      loadElection,
      unloadElection,
      recordAction,
    ],
  );

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>;
}

export function useAppState(): AppStateValue {
  const ctx = useContext(AppStateContext);
  if (!ctx) throw new Error("useAppState must be used within AppStateProvider");
  return ctx;
}
