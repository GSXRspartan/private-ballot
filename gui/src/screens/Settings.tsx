import { useAppState } from "../state/AppState";
import { useTheme, ThemeMode } from "../theme/ThemeProvider";
import { Card } from "../components/ui";

const THEME_OPTIONS: { value: ThemeMode; label: string; hint: string }[] = [
  { value: "system", label: "Automatic (follow OS)", hint: "Uses the operating system light/dark preference." },
  { value: "light", label: "Light", hint: "Always use the light theme." },
  { value: "dark", label: "Dark", hint: "Always use the dark theme." },
];

/**
 * Settings: theme (automatic OS detection + manual override), data
 * directory, default export directory, developer diagnostics. No secrets are
 * stored or accepted anywhere in this application.
 */
export function Settings() {
  const { mode, setMode } = useTheme();
  const { settings, setSetting } = useAppState();

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
          use the official Tari palette with contrast-checked combinations.
        </p>
      </Card>

      <Card title="Directories">
        <div className="form-row">
          <label htmlFor="data-dir">Data directory</label>
          <input
            id="data-dir"
            type="text"
            value={settings.dataDirectory}
            onChange={(e) => setSetting("dataDirectory", e.target.value)}
            placeholder="where election artifacts are kept"
          />
        </div>
        <div className="form-row">
          <label htmlFor="export-dir">Default export directory</label>
          <input
            id="export-dir"
            type="text"
            value={settings.exportDirectory}
            onChange={(e) => setSetting("exportDirectory", e.target.value)}
            placeholder="default target for archives and ballot packages"
          />
        </div>
      </Card>

      <Card title="Developer diagnostics">
        <label className="radio-option">
          <input
            type="checkbox"
            checked={settings.devDiagnostics}
            onChange={(e) => setSetting("devDiagnostics", e.target.checked)}
          />
          Enable developer diagnostics
        </label>
        <p className="form-hint">
          Shows additional boundary detail (command codes and categories) on error surfaces.
          Diagnostics never expose secret material — none exists in the frontend.
        </p>
      </Card>
    </>
  );
}
