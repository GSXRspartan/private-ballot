import { useCallback, useEffect, useRef, useState } from "react";
import { isDesktopShell } from "../../api/client";
import {
  AnchorBundleError,
  bundleDigestKey,
  parseAnchorBundleJson,
  type AnchorBundleV1,
} from "../../wallet/anchorBundle.ts";
import { createBrowserWalletRuntime } from "../../wallet/browserWalletRuntime.ts";
import { browserRecoveryStore } from "../../wallet/recoveryStore.ts";
import type { AnchorRecoveryRecord } from "../../wallet/recoveryStore.ts";
import {
  assessAnchorWorkflow,
  phaseLabel,
} from "../../wallet/anchorWorkflow.ts";
import {
  adapterForKind,
  defaultPublishDriver,
  providerErrorMessage,
  recoveryWriterFor,
} from "../../anchor/browserAnchorPublish.ts";
import { Notice } from "../../components/ui";
import type { WalletEntry } from "../../wallet/settingsState.ts";
import { initialWalletEntries, walletEntryButton, walletEntryStatus } from "../../wallet/settingsState.ts";

const VERIFY_ATTEMPTS = 30;
const VERIFY_INTERVAL_MS = 4000;
const APPROVAL_TIMEOUT_MS = 10 * 60 * 1000;

export function BrowserAnchorPublishPanel() {
  const [bundle, setBundle] = useState<AnchorBundleV1 | null>(null);
  const [bundleError, setBundleError] = useState<string | null>(null);
  const [entries, setEntries] = useState<WalletEntry[]>(initialWalletEntries);
  const [phaseOverride, setPhaseOverride] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recovery, setRecovery] = useState<AnchorRecoveryRecord | null>(null);
  const runtimeRef = useRef<ReturnType<typeof createBrowserWalletRuntime> | null>(null);
  const recoveryRef = useRef<ReturnType<typeof browserRecoveryStore> | null>(null);

  useEffect(() => {
    if (isDesktopShell() || runtimeRef.current) return;
    const runtime = createBrowserWalletRuntime(
      window as unknown as Parameters<typeof createBrowserWalletRuntime>[0],
    );
    runtimeRef.current = runtime;
    recoveryRef.current = browserRecoveryStore();
    void runtime.probeAll((kind, entry) => {
      setEntries((previous) =>
        previous.map((candidate) => (candidate.kind === kind ? entry : candidate)),
      );
    });
  }, []);

  const onImportFile = useCallback(async (file: File) => {
    setBundleError(null);
    setBundle(null);
    setPhaseOverride(null);
    const text = await file.text();
    try {
      const parsed = parseAnchorBundleJson(text);
      setBundle(parsed);
      setRecovery(recoveryRef.current?.load(bundleDigestKey(parsed)) ?? null);
    } catch (error) {
      setBundleError(
        error instanceof AnchorBundleError
          ? error.message
          : "the bundle file is not valid JSON",
      );
    }
  }, []);

  const walletConnected = entries.some(
    (entry) => entry.kind === "sapient" || entry.kind === "universe",
  ) && entries.some((entry) => entry.phase.kind === "connected" || entry.phase.kind === "ready");
  let walletNetworkName: string | null = null;
  for (const entry of entries) {
    if (entry.phase.kind === "connected") {
      walletNetworkName = entry.phase.network;
      break;
    }
  }

  const phase = bundle
    ? assessAnchorWorkflow({
        bundle,
        bundleInvalidReason: null,
        walletConnected,
        walletNetworkName,
        recovery,
      })
    : null;

  const displayPhase = phaseOverride ?? (phase ? phaseLabel(phase) : null);

  const onConnect = useCallback((kind: "sapient" | "universe") => {
    runtimeRef.current?.connect(kind, (kindOf, entry) => {
      setEntries((previous) =>
        previous.map((candidate) => (candidate.kind === kindOf ? entry : candidate)),
      );
    });
  }, []);

  const onPublish = useCallback(async () => {
    if (!bundle || !recoveryRef.current) return;
    if (recovery !== null) {
      setPhaseOverride("A saved anchor request or transaction exists. Resolve it before creating another request.");
      return;
    }
    const connectedEntry = entries.find((entry) => entry.phase.kind === "connected");
    if (!connectedEntry) {
      setPhaseOverride("Connect a Tari wallet first.");
      return;
    }
    setBusy(true);
    setPhaseOverride("Waiting for the wallet to review the anchor transaction…");
    const writer = recoveryWriterFor(
      recoveryRef.current,
      bundleDigestKey(bundle),
    );
    try {
      const adapter = adapterForKind(connectedEntry.kind, window as unknown as Parameters<typeof adapterForKind>[1]);
      const driver = defaultPublishDriver({
        verifyAttempts: VERIFY_ATTEMPTS,
        verifyIntervalMs: VERIFY_INTERVAL_MS,
      });
      await driver.connect(adapter);
      const requestId = await driver.createRequest(adapter, bundle);
      writer.saveSubmittedAwaitingApproval(requestId);
      setPhaseOverride("Waiting for the wallet to approve the anchor transaction…");
      const summary = await driver.waitForApproval(
        adapter,
        requestId,
        APPROVAL_TIMEOUT_MS,
      );
      if (summary.status !== "approved") {
        const detail =
          typeof summary.error === "string" && summary.error.length > 0
            ? summary.error
            : `the wallet ${summary.status} the request`;
        setRecovery(recoveryRef.current.load(bundleDigestKey(bundle)));
        setPhaseOverride(`${detail} The saved request remains blocked; check wallet history before any further action.`);
        setBusy(false);
        return;
      }
      setPhaseOverride("Submitting the approved transaction…");
      writer.saveSubmitInFlight(requestId);
      setRecovery(recoveryRef.current.load(bundleDigestKey(bundle)));
      const transactionId = await driver.submit(adapter, requestId);
      writer.saveApprovedSubmitted(transactionId);
      setRecovery(recoveryRef.current.load(bundleDigestKey(bundle)));
      setPhaseOverride("Verifying the on-chain anchor event against this election…");
      const outcome = await driver.verify(adapter, bundle, transactionId);
      if (outcome.kind === "verified") {
        writer.saveVerified(transactionId);
        setRecovery(recoveryRef.current.load(bundleDigestKey(bundle)));
        setPhaseOverride(
          `Verified: the on-chain anchor matches this election (transaction ${transactionId.slice(0, 16)}…). The anchor is published.`,
        );
      } else if (outcome.kind === "pending") {
        setPhaseOverride(
          `${outcome.detail ?? "The anchor transaction is not final yet"}. Reopen this page later to re-verify; nothing is ever resubmitted automatically.`,
        );
      } else {
        setRecovery(recoveryRef.current.load(bundleDigestKey(bundle)));
        setPhaseOverride(
          `${outcome.message} (transaction ${transactionId}) Nothing was resubmitted; check the wallet history before trying again.`,
        );
      }
    } catch (error) {
      setPhaseOverride(
        `${providerErrorMessage(error)} Nothing was resubmitted; check the wallet history before trying again.`,
      );
    } finally {
      setBusy(false);
    }
  }, [bundle, entries, recovery]);

  return (
    <div className="browser-anchor-panel">
      <p className="form-hint">
        Publish the election anchor from a normal web browser using a Tari wallet
        (Sapient or Tari Universe). Import the anchor bundle that the desktop
        application exported after verifying the final archive. The bundle carries
        the exact verified anchor arguments; this page never rebuilds or alters
        them. Nothing here can touch the desktop application's wallet connection.
      </p>
      <div className="form-row">
        <label htmlFor="browser-anchor-bundle-file">Anchor bundle (JSON)</label>
        <input
          id="browser-anchor-bundle-file"
          type="file"
          accept=".json,application/json"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void onImportFile(file);
          }}
        />
      </div>
      {bundleError && <Notice tone="error">{bundleError}</Notice>}
      {bundle && (
        <div className="field-list anchor-deployment-fields">
          <div className="form-row">
            <label>Bundle</label>
            <span>
              {bundle.network} · {bundle.template.function} · digest{" "}
              {bundle.anchorArgs.anchorDigestHex.slice(0, 12)}…
            </span>
          </div>
          <div className="form-row">
            <label>Wallet</label>
            <span>
              {entries
                .map((entry) => `${entry.label}: ${walletEntryStatus(entry)}`)
                .join(" · ")}
            </span>
          </div>
          {displayPhase && (
            <div className="form-row">
              <label>Status</label>
              <span>{displayPhase}</span>
            </div>
          )}
        </div>
      )}
      {bundle && (
        <div className="btn-row">
          {entries
            .filter((entry) => !walletEntryButton(entry).hidden)
            .map((entry) => {
              const button = walletEntryButton(entry);
              return (
                <button
                  key={entry.kind}
                  type="button"
                  className="btn btn-secondary"
                  disabled={button.disabled || busy}
                  onClick={() => onConnect(entry.kind)}
                >
                  {entry.label}: {button.label}
                </button>
              );
            })}
          {phase?.kind === "ready" && (
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => void onPublish()}
            >
              {busy ? "Working…" : "Ask wallet to publish anchor"}
            </button>
          )}
        </div>
      )}
      <p className="form-hint">
        The wallet shows the exact transaction and asks for explicit approval before
        anything is signed or submitted. If the page reloads mid-approval, import the
        same bundle again and check the wallet's own history for the pending request;
        this page never recreates or resubmits a transaction on its own.
      </p>
    </div>
  );
}
