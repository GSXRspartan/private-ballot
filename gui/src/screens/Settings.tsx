import { useCallback, useEffect, useRef, useState } from "react";
import { pickDirectory } from "../api/dialog";
import { isDesktopShell } from "../api/client";
import { useAppState } from "../state/AppState";
import { useTheme, ThemeMode } from "../theme/ThemeProvider";
import { Card } from "../components/ui";
import { createBrowserWalletRuntime } from "../wallet/browserWalletRuntime";
import { initialWalletEntries, walletEntryButton, walletEntryStatus } from "../wallet/settingsState";
import type { ProviderKind } from "../wallet/types";
import type { WalletEntry } from "../wallet/settingsState";

const THEME_OPTIONS: { value: ThemeMode; label: string; hint: string }[] = [
  { value: "system", label: "Automatic (follow OS)", hint: "Uses the operating system light/dark preference." },
  { value: "light", label: "Light", hint: "Always use the light theme." },
  { value: "dark", label: "Dark", hint: "Always use the dark theme." },
];

function BrowserWalletCard() {
  const [entries, setEntries] = useState<WalletEntry[]>(initialWalletEntries);
  const runtimeRef = useRef<ReturnType<typeof createBrowserWalletRuntime> | null>(null);
  const [probed, setProbed] = useState(false);

  const applyEntry = useCallback((kind: ProviderKind, entry: WalletEntry) => {
    setEntries((previous) =>
      previous.map((candidate) => (candidate.kind === kind ? entry : candidate)),
    );
  }, []);

  useEffect(() => {
    if (probed) return;
    setProbed(true);
    const runtime = createBrowserWalletRuntime(
      window as unknown as Parameters<typeof createBrowserWalletRuntime>[0],
    );
    runtimeRef.current = runtime;
    void runtime.probeAll(applyEntry);
  }, [probed, applyEntry]);

  const onConnect = useCallback(
    (kind: ProviderKind) => {
      runtimeRef.current?.connect(kind, applyEntry);
    },
    [applyEntry],
  );

  return (
    <Card title="Tari Wallet (browser)">
      <p className="form-hint">
        Connection status for browser Tari wallets. This is only used when this application runs
        in a normal web browser to publish an election anchor; the desktop application uses its
        own local wallet connection. No balances, transaction history, or wallet contents are
        displayed or stored here.
      </p>
      {entries.map((entry) => {
        const button = walletEntryButton(entry);
        return (
          <div className="form-row" key={entry.kind}>
            <label>{entry.label}</label>
            <div className="file-row">
              <span>{walletEntryStatus(entry)}</span>
              {button.hidden ? null : (
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={button.disabled}
                  onClick={() => onConnect(entry.kind)}
                >
                  {button.label}
                </button>
              )}
            </div>
          </div>
        );
      })}
      <p className="form-hint">
        Connecting only authorizes this page to ask the wallet to review and approve
        transactions you explicitly submit. The application never receives keys, seed
        phrases, or the wallet's private contents.
      </p>
    </Card>
  );
}

/**
 * Settings: theme (automatic OS detection + manual override), data
 * directory, default export directory, developer diagnostics. No secrets are
 * stored or accepted anywhere in this application.
 */
export function Settings() {
  const { mode, setMode } = useTheme();
  const { settings, setSetting, shellAvailable } = useAppState();

  const onBrowse = async (key: "dataDirectory" | "exportDirectory", title: string) => {
    const picked = await pickDirectory(title);
    if (picked !== null) setSetting(key, picked);
  };

  return (
    <>
      <h1 className="screen-header">Settings</h1>
      <p className="screen-lede">
        Application preferences. Settings never include credentials, tokens, keys, or wallet
        material.
      </p>

      <Card title="Theme">
        <div className="radio-group" role="radiogroup" aria-label="Theme">
          {THEME_OPTIONS.map((option) => (
            <label key={option.value} className="radio-option" title={option.hint}>
              <input
                type="radio"
                name="theme"
                value={option.value}
                checked={mode === option.value}
                onChange={() => setMode(option.value)}
              />
              {option.label}
            </label>
          ))}
        </div>
        <p className="form-hint">
          Automatic mode follows the OS and updates live when the OS theme changes. Both themes
          use the same navy and purple community palette.
        </p>
      </Card>

      {!isDesktopShell() ? <BrowserWalletCard /> : null}

      <Card title="Directories">
        <p className="form-hint">
          These directories are optional overrides; leave blank to use the application's
          default location; the app does not move existing archives if you change the
          export directory later.
        </p>
        <div className="form-row">
          <label htmlFor="data-dir">Data directory</label>
          <div className="file-row">
            <input
              id="data-dir"
              type="text"
              value={settings.dataDirectory}
              onChange={(e) => setSetting("dataDirectory", e.target.value)}
              placeholder="Using application default"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onBrowse("dataDirectory", "Choose data directory")}
            >
              Browse
            </button>
          </div>
          <p className="form-hint">
            Where the application keeps its local working data (draft elections, saved
            voter credentials, private-intake inbox, and anchor lifecycle sidecars).
          </p>
        </div>
        <div className="form-row">
          <label htmlFor="export-dir">Default export directory</label>
          <div className="file-row">
            <input
              id="export-dir"
              type="text"
              value={settings.exportDirectory}
              onChange={(e) => setSetting("exportDirectory", e.target.value)}
              placeholder="Using application default"
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!shellAvailable}
              onClick={() => void onBrowse("exportDirectory", "Choose default export directory")}
            >
              Browse
            </button>
          </div>
          <p className="form-hint">
            Suggested destination for exported election packages, ballot packages, and
            finalized archives. Existing exports are never moved.
          </p>
        </div>
      </Card>

      <Card title="Advanced / Developer diagnostics">
        <label className="radio-option">
          <input
            type="checkbox"
            checked={settings.devDiagnostics}
            onChange={(e) => setSetting("devDiagnostics", e.target.checked)}
          />
          Enable developer diagnostics
        </label>
        <p className="form-hint">
          Off by default. When enabled, shows extra technical detail for troubleshooting
          in the footer: backend boundary, target network, lifecycle state, and the
          configured data-directory override. Diagnostics never expose credentials,
          tokens, wallet material, private keys, voter credentials, or transport
          authority secrets — no secret material exists in the frontend.
        </p>
      </Card>
    </>
  );
}
