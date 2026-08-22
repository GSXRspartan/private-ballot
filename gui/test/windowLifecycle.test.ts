// Window-lifecycle regression tests (Failure 4 — minimize must not lose the
// main window).
//
// Root cause (established by source inspection of the pinned tao 0.35.3 /
// wry 0.55.1 / tauri 2.11.5 stack): NO application, configuration, tao, or wry
// code path hides/closes/destroys the window on a plain minimize — tao's
// SC_MINIMIZE handler only sets a flag and calls DefWindowProc, and wry's
// WM_SIZE handler explicitly skips SIZE_MINIMIZED. The observed "window gone
// from taskbar/Alt-Tab, only the Tao Thread Event Target survives, process
// alive" is the Chromium/WebView2 *native window occlusion* pathology: when the
// window is minimized/occluded, Chromium's occlusion calculation can release
// the composited window surface and, on some driver/OS combinations, leave the
// window unrestorable.
//
// Fix (pure configuration, no code / no unsafe / no Win32 / no tray / no
// framework bump): the main window disables the `CalculateNativeWinOcclusion`
// Chromium feature via the supported `additionalBrowserArgs`, while preserving
// wry's default disables (which `additionalBrowserArgs` otherwise replaces).
//
// These tests pin the fix and the invariants that keep minimize == minimize:
// the shell must never hide/minimize/skip-taskbar/tray/destroy the window, and
// the frontend must never touch the Tauri window API (its capability grants no
// window permissions anyway).
//
// A real Windows minimize→restore regression is still REQUIRED after this
// change; the behavior cannot be exercised headlessly.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const conf = JSON.parse(readProjectFile("src-tauri/tauri.conf.json"));
const shell = readProjectFile("src-tauri/src/lib.rs");

// -------------------------------------------------------------------------
// Config fix: disable native window occlusion, preserve wry defaults.
// -------------------------------------------------------------------------

describe("main window WebView2 occlusion fix", () => {
  const mainWindow = (conf.app?.windows ?? []).find(
    (w: { label?: string }) => w.label === "main",
  );

  it("has a main window with additionalBrowserArgs configured", () => {
    assert.ok(mainWindow, "a main window is configured");
    assert.equal(typeof mainWindow.additionalBrowserArgs, "string");
  });

  it("disables CalculateNativeWinOcclusion (the minimize-loss root cause)", () => {
    const args: string = mainWindow.additionalBrowserArgs;
    const disableFeatures = args
      .split(/\s+/)
      .find((a) => a.startsWith("--disable-features="));
    assert.ok(disableFeatures, "a --disable-features flag is present");
    const features = disableFeatures.slice("--disable-features=".length).split(",");
    assert.ok(
      features.includes("CalculateNativeWinOcclusion"),
      "CalculateNativeWinOcclusion must be disabled to survive minimize/occlusion",
    );
  });

  it("preserves wry's default browser-arg disables (they are replaced otherwise)", () => {
    const args: string = mainWindow.additionalBrowserArgs;
    for (const feature of ["msWebOOUI", "msPdfOOUI", "msSmartScreenProtection"]) {
      assert.ok(args.includes(feature), `wry default disable preserved: ${feature}`);
    }
  });

  it("does not introduce a tray, and does not hide/skip-taskbar the window via config", () => {
    const raw = JSON.stringify(conf);
    assert.doesNotMatch(raw, /trayIcon/i);
    // The window is a normal visible taskbar window (no skipTaskbar / hidden).
    assert.notEqual(mainWindow.skipTaskbar, true);
    assert.notEqual(mainWindow.visible, false);
  });
});

// -------------------------------------------------------------------------
// The shell never conflates minimize with hide/close/destroy, and never adds a
// tray/minimize-to-tray architecture.
// -------------------------------------------------------------------------

describe("shell window-lifecycle policy", () => {
  it("never programmatically hides/minimizes/skip-taskbars/destroys a window", () => {
    for (const forbidden of [
      ".minimize(",
      ".set_minimized(",
      "set_skip_taskbar",
      "skip_taskbar",
      ".hide()",
      "set_visible(false)",
      ".destroy()",
      "TrayIcon",
      "tray_icon",
      "SystemTray",
      "prevent_close",
    ]) {
      assert.ok(
        !shell.includes(forbidden),
        `shell must not use window/tray operation: ${forbidden}`,
      );
    }
  });

  it("the RunEvent handler reacts only to Exit/ExitRequested and only reaps Tor", () => {
    // No window-event handling (on_window_event / WindowEvent / CloseRequested /
    // Minimized) exists, so minimize can never be routed into close/hide logic.
    assert.doesNotMatch(shell, /on_window_event/);
    assert.doesNotMatch(shell, /WindowEvent::/);
    assert.match(
      shell,
      /RunEvent::ExitRequested \{ \.\. \} \| tauri::RunEvent::Exit/,
    );
    // The only teardown action is the owned-Tor reap (existing crash repair).
    assert.match(shell, /shutdown_managed_tor_on_exit/);
    assert.match(shell, /shutdown_intake_on_exit/);
  });
});

// -------------------------------------------------------------------------
// The frontend cannot manipulate the native window at all.
// -------------------------------------------------------------------------

describe("frontend never touches the Tauri window API", () => {
  function walk(dir: URL): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const child = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, dir);
      if (entry.isDirectory()) out.push(...walk(child));
      else if (/\.(ts|tsx)$/.test(entry.name)) out.push(readFileSync(child, "utf8"));
    }
    return out;
  }

  it("imports no window/webviewWindow module and calls no window ops", () => {
    const sources = walk(new URL("../src/", import.meta.url)).join("\n");
    for (const forbidden of [
      "@tauri-apps/api/window",
      "@tauri-apps/api/webviewWindow",
      "getCurrentWindow",
      "getCurrentWebviewWindow",
      "WebviewWindow",
    ]) {
      assert.ok(!sources.includes(forbidden), `frontend must not use: ${forbidden}`);
    }
  });

  it("the capability grants only dialog permissions (no window control)", () => {
    const cap = JSON.parse(readProjectFile("src-tauri/capabilities/default.json"));
    assert.deepEqual(cap.permissions, ["dialog:allow-open", "dialog:allow-save"]);
    assert.ok(
      !cap.permissions.some((p: string) => p.startsWith("core:window")),
      "no core:window permission is granted to the webview",
    );
  });
});
