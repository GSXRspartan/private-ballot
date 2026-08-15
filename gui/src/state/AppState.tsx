import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { api, BackendError, isDesktopShell } from "../api/client";
import {
  newCreateElectionSession,
  type CreateElectionSessionState,
} from "../creation";
import { RequestGenerationGate } from "../requestGeneration";
import type {
  GuiCommandError,
  GuiElectionSummaryV1,
  GuiElectionWorkspaceResumeResultV1,
  GuiElectionWorkspaceSummaryV1,
  GuiParticipationSummaryV1,
  GuiTallySummaryV1,
} from "../api/types";

export interface RecentAction {
  at: string;
  label: string;
}

export interface AppSettings {
  dataDirectory: string;
  exportDirectory: string;
  devDiagnostics: boolean;
}

/** Session-only record of the artifact paths selected for the loaded election.
 *  Not persisted; cleared on unload. */
export interface SelectedArtifactPaths {
  manifest: string;
  registry: string;
  optionSet: string;
}

interface AppStateValue {
  shellAvailable: boolean;
  election: GuiElectionSummaryV1 | null;
  tally: GuiTallySummaryV1 | null;
  /** Privacy-aware participation summary (backend-authoritative; cleared on
   *  unload). Numeric fields are null while sealed. */
  participation: GuiParticipationSummaryV1 | null;
  workspaces: GuiElectionWorkspaceSummaryV1[];
  recentActions: RecentAction[];
  settings: AppSettings;
  /** Last structured backend error, or null when none is active. */
  backendError: GuiCommandError | null;
  /** Paths chosen for the loaded election (session-only, not persisted). */
  selectedArtifactPaths: SelectedArtifactPaths | null;
  setSetting: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
  refreshElection: () => Promise<void>;
  refreshWorkspaces: () => Promise<void>;
  /** Refreshes the participation summary from the backend. Does not disclose
   *  sealed values; the backend returns null numerics while sealed. */
  refreshParticipation: () => Promise<void>;
  runLifecycle: (action: "open" | "close" | "verify" | "finalize") => Promise<void>;
  loadElection: (
    manifestPath: string,
    registryPath: string,
    optionSetPath: string,
  ) => Promise<void>;
  resumeElectionWorkspace: (
    workspaceId: string,
  ) => Promise<GuiElectionWorkspaceResumeResultV1>;
  unloadElection: () => Promise<void>;
  dismissError: () => void;
  recordAction: (label: string) => void;
  /** Session-only Create Election editing buffers; never persisted to disk. */
  createElectionSession: CreateElectionSessionState | null;
  updateCreateElectionSession: (
    update: (current: CreateElectionSessionState) => CreateElectionSessionState,
  ) => void;
  replaceCreateElectionSession: (next: CreateElectionSessionState | null) => void;
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
  const [participation, setParticipation] =
    useState<GuiParticipationSummaryV1 | null>(null);
  const [workspaces, setWorkspaces] = useState<GuiElectionWorkspaceSummaryV1[]>([]);
  const [recentActions, setRecentActions] = useState<RecentAction[]>([]);
  const [settings, setSettings] = useState<AppSettings>(readSettings);
  const [backendError, setBackendError] = useState<GuiCommandError | null>(null);
  const [selectedArtifactPaths, setSelectedArtifactPaths] =
    useState<SelectedArtifactPaths | null>(null);
  const [createElectionSession, setCreateElectionSession] =
    useState<CreateElectionSessionState | null>(null);
  // Monotonic token for non-authoritative presentation refreshes. A late
  // response must never overwrite a newer election or lifecycle state.
  const participationRequestGenerationRef = useRef(new RequestGenerationGate());

  const recordAction = useCallback((label: string) => {
    setRecentActions((prev) =>
      [{ at: new Date().toISOString(), label }, ...prev].slice(0, 12),
    );
  }, []);

  const captureError = useCallback((error: unknown) => {
    if (error instanceof BackendError) {
      setBackendError(error.payload);
    } else {
      setBackendError({
        code: "GUI_UNEXPECTED_ERROR",
        category: "INVALID_INPUT",
        context: null,
        message: "an unexpected frontend/backend boundary error occurred",
      });
    }
  }, []);

  const dismissError = useCallback(() => setBackendError(null), []);

  const updateCreateElectionSession = useCallback(
    (update: (current: CreateElectionSessionState) => CreateElectionSessionState) => {
      setCreateElectionSession((current) => update(current ?? newCreateElectionSession()));
    },
    [],
  );
  const replaceCreateElectionSession = useCallback(
    (next: CreateElectionSessionState | null) => setCreateElectionSession(next),
    [],
  );

  const refreshElection = useCallback(async () => {
    try {
      const summary = await api.electionSummary();
      setElection(summary);
      setBackendError(null);
    } catch (error) {
      captureError(error);
    }
  }, [captureError]);

  const refreshWorkspaces = useCallback(async () => {
    if (!isDesktopShell()) {
      setWorkspaces([]);
      return;
    }
    try {
      const summaries = await api.listElectionWorkspaces();
      setWorkspaces(summaries);
    } catch (error) {
      captureError(error);
      setWorkspaces([]);
    }
  }, [captureError]);

  const refreshParticipation = useCallback(async () => {
    if (!isDesktopShell()) {
      setParticipation(null);
      return;
    }
    const requestGeneration = participationRequestGenerationRef.current.begin();
    try {
      const summary = await api.participationSummary();
      if (participationRequestGenerationRef.current.isCurrent(requestGeneration)) {
        setParticipation(summary);
      }
    } catch (error) {
      // No election loaded is a NORMAL application state, not an error: a
      // fresh startup must never display a red no-active-election error
      // merely because there is nothing loaded yet. Real failures of an
      // actual user operation are still surfaced.
      if (error instanceof BackendError && error.payload.code === "GUI_NO_ACTIVE_ELECTION") {
        if (participationRequestGenerationRef.current.isCurrent(requestGeneration)) setParticipation(null);
        return;
      }
      // Participation refresh failures are non-fatal: the dashboard falls
      // back to its neutral state. A structured error is still surfaced.
      captureError(error);
      if (participationRequestGenerationRef.current.isCurrent(requestGeneration)) setParticipation(null);
    }
  }, [captureError]);

  useEffect(() => {
    if (shellAvailable) {
      void refreshElection();
      void refreshParticipation();
      void refreshWorkspaces();
    }
  }, [shellAvailable, refreshElection, refreshParticipation, refreshWorkspaces]);

  const loadElection = useCallback(
    async (manifestPath: string, registryPath: string, optionSetPath: string) => {
      try {
        const summary = await api.loadElection(manifestPath, registryPath, optionSetPath);
        setElection(summary);
        setTally(null);
        setParticipation(null);
        setBackendError(null);
        setSelectedArtifactPaths({
          manifest: manifestPath,
          registry: registryPath,
          optionSet: optionSetPath,
        });
        recordAction(`Loaded election ${summary.election_id_text ?? summary.election_id_hex}`);
        void refreshParticipation();
        void refreshWorkspaces();
      } catch (error) {
        captureError(error);
        throw error;
      }
    },
    [captureError, recordAction, refreshParticipation, refreshWorkspaces],
  );

  const resumeElectionWorkspace = useCallback(
    async (workspaceId: string) => {
      try {
        const result = await api.resumeElectionWorkspace(workspaceId);
        setElection(result.election);
        setTally(null);
        setParticipation(null);
        setBackendError(null);
        setSelectedArtifactPaths(null);
        if (result.draft) {
          setCreateElectionSession(null);
        }
        recordAction(
          result.election
            ? `Resumed election ${result.election.election_id_text ?? result.election.election_id_hex}`
            : "Resumed election draft",
        );
        if (result.election) void refreshParticipation();
        void refreshWorkspaces();
        return result;
      } catch (error) {
        captureError(error);
        throw error;
      }
    },
    [captureError, recordAction, refreshParticipation, refreshWorkspaces],
  );

  const unloadElection = useCallback(async () => {
    try {
      participationRequestGenerationRef.current.invalidate();
      await api.unloadElection();
      setElection(null);
      setTally(null);
      setParticipation(null);
      setBackendError(null);
      setSelectedArtifactPaths(null);
      recordAction("Unloaded election session");
      void refreshWorkspaces();
    } catch (error) {
      captureError(error);
    }
  }, [captureError, recordAction, refreshWorkspaces]);

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
        // Lifecycle transitions change the disclosure policy; refresh the
        // participation summary so the dashboard reflects the new visibility
        // state. Tally is cleared because the previous (possibly sealed)
        // tally is no longer current.
        setTally(null);
        setBackendError(null);
        recordAction(labels[action]);
        void refreshParticipation();
        void refreshWorkspaces();
      } catch (error) {
        captureError(error);
      }
    },
    [captureError, recordAction, refreshParticipation, refreshWorkspaces],
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
      participation,
      workspaces,
      recentActions,
      settings,
      backendError,
      selectedArtifactPaths,
      setSetting,
      refreshElection,
      refreshWorkspaces,
      refreshParticipation,
      runLifecycle,
      loadElection,
      resumeElectionWorkspace,
      unloadElection,
      dismissError,
      recordAction,
      createElectionSession,
      updateCreateElectionSession,
      replaceCreateElectionSession,
    }),
    [
      shellAvailable,
      election,
      tally,
      participation,
      workspaces,
      recentActions,
      settings,
      backendError,
      selectedArtifactPaths,
      setSetting,
      refreshElection,
      refreshWorkspaces,
      refreshParticipation,
      runLifecycle,
      loadElection,
      resumeElectionWorkspace,
      unloadElection,
      dismissError,
      recordAction,
      createElectionSession,
      updateCreateElectionSession,
      replaceCreateElectionSession,
    ],
  );

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>;
}

export function useAppState(): AppStateValue {
  const ctx = useContext(AppStateContext);
  if (!ctx) throw new Error("useAppState must be used within AppStateProvider");
  return ctx;
}
