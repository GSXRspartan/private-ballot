import { useEffect, useState } from "react";

import { api, isDesktopShell } from "../api/client";
import type { ShellInfoV1 } from "../api/types";
import TariLogo from "../branding/TariLogo";
import { Card, Field, Notice, Pill } from "../components/ui";

/**
 * About: application identity, branding attribution, and the single fuller scope
 * notice. The compact product-status label "Governance Pilot" lives here as a
 * field and in the toolbar; this screen is the only place the longer scope
 * statement appears.
 */
export function About() {
  const [info, setInfo] = useState<ShellInfoV1 | null>(null);

  useEffect(() => {
    if (isDesktopShell()) {
      api
        .shellInfo()
        .then(setInfo)
        .catch(() => setInfo(null));
    }
  }, []);

  return (
    <>
      <h1 className="screen-header">About</h1>

      <Card title="Application">
        <div className="brand">
          <TariLogo />
          <span className="brand-name">
            Private <span className="brand-name-accent">Ballot</span>
          </span>
        </div>
        <div className="field-list">
          <Field label="Status">
            <Pill tone="brand">Governance Pilot</Pill>
          </Field>
          <Field label="Version">{info?.shell_version ?? "0.1.0 (browser preview)"}</Field>
          <Field label="Backend boundary">
            {info?.gui_core_boundary ?? "gui-core typed commands (in process, no server)"}
          </Field>
          <Field label="Stack">Tauri 2 · React · TypeScript · Vite (system WebView)</Field>
        </div>
      </Card>

      <Card title="Branding attribution">
        <p className="card-body">
          The Tari logo and the Tari color scales are official assets of the Tari Project,
          taken unmodified from the official Tari Ootle repository (BSD-3-Clause, The Tari
          Project). The logo artwork is not redrawn or approximated. Typography references
          Poppins, the official Tari interface typeface, via the operating system.
        </p>
      </Card>

      <Card title="Architecture">
        <p className="card-body">
          All cryptography, canonical encoding, hashing, proof verification, tallying, archive
          construction, replay verification, and anchor lifecycle logic live in the Rust
          backend and are reached only through gui-core typed commands. This frontend contains
          no protocol logic and holds no secrets.
        </p>
      </Card>

      <Notice tone="info">
        <strong>Scope.</strong>{" "}
        {info?.binding_notice ??
          "This release is intended for governance pilots. Binding governance use requires the applicable review and authorization process."}
      </Notice>
    </>
  );
}
