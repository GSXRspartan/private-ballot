import { useEffect, useState } from "react";

import { api, isDesktopShell } from "../api/client";
import type { ShellInfoV1 } from "../api/types";
import PrivateBallotEmblem from "../branding/PrivateBallotEmblem";
import {
  DONATION_DISCLAIMER,
  DONATION_XTM_ADDRESS,
  DONATION_YAT,
} from "../branding/donation";
import {
  APP_IDENTITY_TAG,
  APP_NAME,
  APP_NETWORK_LABEL,
  APP_RELEASE_STATUS,
  APP_STATUS_LABEL,
  APP_VERSION,
  COMMUNITY_DISCLAIMER,
} from "../branding/identity";
import { QrCode } from "../components/QrCode";
import { Card, CopyButton, DetailsSection, Field, Notice, Pill } from "../components/ui";

/**
 * About: project identity, open-source acknowledgements, plain architecture
 * explanation, and the single fuller scope notice.
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

      <Card title="Project identity">
        <div className="brand about-brand">
          <PrivateBallotEmblem variant="full" className="about-emblem" />
          <span className="identity-text">
            <span className="identity-name">{APP_NAME}</span>
            <span className="identity-subtitle">{APP_IDENTITY_TAG}</span>
          </span>
        </div>
        <div className="field-list">
          <Field label="Release status">
            <Pill tone="warn">{APP_RELEASE_STATUS}</Pill>{" "}
            <span className="form-hint">
              Experimental pre-release software; not audited for production governance use.
            </span>
          </Field>
          <Field label="Network">{APP_NETWORK_LABEL}</Field>
          <Field label="Purpose">
            <Pill tone="brand">{APP_STATUS_LABEL}</Pill>
          </Field>
          <Field label="Version">{info?.shell_version ?? `${APP_VERSION} (browser preview)`}</Field>
        </div>
        <Notice tone="info">{COMMUNITY_DISCLAIMER}</Notice>
      </Card>

      <Card title="Open-source acknowledgements">
        <p className="card-body">
          Private Ballot builds on open-source technology from the Tari ecosystem, including
          the Tari Triptych implementation (BSD-3-Clause, The Tari Project), and on Tari Ootle
          for optional public anchoring. These are licence acknowledgements only: they do not
          make this an official Tari Labs application, and they imply no endorsement of this
          independent open-source project.
        </p>
        <div className="field-list">
          <Field label="Stack">Tauri 2 · React · TypeScript · Vite (system WebView)</Field>
        </div>
        <DetailsSection summary="Technical details">
          <div className="field-list">
            <Field label="Backend boundary">
              {info?.gui_core_boundary ?? "typed commands (in process, no server)"}
            </Field>
          </div>
        </DetailsSection>
      </Card>

      <Card title="Architecture">
        <p className="card-body">
          Everything security-sensitive — the eligibility proofs, the checks that a ballot is
          valid, the tally, and the saved election record — is implemented in the Rust backend.
          This window is only an interface: it does not perform cryptographic verification
          itself. Private keys, voter credentials, and other secret material stay behind the
          backend boundary; this interface never receives them.
        </p>
      </Card>

      <Notice tone="info">
        <strong>Scope.</strong>{" "}
        {info?.binding_notice ??
          "This release is intended for governance pilots. Binding governance use requires the applicable review and authorization process."}
      </Notice>

      <Card title="Donate to the dev">
        <p className="card-body">{DONATION_DISCLAIMER}</p>
        <div className="donate-grid">
          <section className="donate-method" aria-label="XTM donation">
            <h4 className="donate-method-title">XTM</h4>
            <p className="donate-address">{DONATION_XTM_ADDRESS}</p>
            <DonateActions
              value={DONATION_XTM_ADDRESS}
              copyLabel="Copy address"
              copyAriaLabel="Copy XTM donation address"
              qrToggleLabel="XTM QR code"
              qrRegionId="donate-xtm-qr"
              qrLabel="QR code encoding the XTM donation address"
              qrCaption="XTM receive address"
            />
          </section>
          <section className="donate-method" aria-label="Yat donation">
            <h4 className="donate-method-title">Yat</h4>
            <p className="yat-display">{DONATION_YAT}</p>
            <DonateActions
              value={DONATION_YAT}
              copyLabel="Copy Yat"
              copyAriaLabel="Copy Yat"
              qrToggleLabel="Yat QR code"
              qrRegionId="donate-yat-qr"
              qrLabel="QR code encoding the Yat"
              qrCaption="Yat"
            />
            <p className="donate-yat-note">
              Other supported donation addresses are available through the Yat.
            </p>
          </section>
        </div>
      </Card>
    </>
  );
}

/** Copy + locally-expandable QR actions for one public donation
 *  destination. No wallet connection or payment behavior — these are
 *  static public constants only. */
function DonateActions({
  value,
  copyLabel,
  copyAriaLabel,
  qrToggleLabel,
  qrRegionId,
  qrLabel,
  qrCaption,
}: {
  value: string;
  copyLabel: string;
  copyAriaLabel: string;
  qrToggleLabel: string;
  qrRegionId: string;
  qrLabel: string;
  qrCaption: string;
}) {
  const [showQr, setShowQr] = useState(false);
  return (
    <>
      <div className="btn-row">
        <CopyButton value={value} label={copyLabel} ariaLabel={copyAriaLabel} />
        <button
          type="button"
          className="btn btn-secondary"
          aria-expanded={showQr}
          aria-controls={qrRegionId}
          aria-label={showQr ? `Hide ${qrToggleLabel}` : `Show ${qrToggleLabel}`}
          onClick={() => setShowQr((current) => !current)}
        >
          {showQr ? "Hide QR" : "Show QR"}
        </button>
      </div>
      {showQr && (
        <div className="donate-qr" id={qrRegionId}>
          <QrCode value={value} label={qrLabel} />
          <span className="donate-qr-caption">{qrCaption}</span>
        </div>
      )}
    </>
  );
}
