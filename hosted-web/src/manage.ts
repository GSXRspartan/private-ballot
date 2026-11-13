/**
 * Hosted organizer: manage an existing self-service election.
 *
 * The organizer credential is resolved either from a saved access file or
 * by manual entry; it lives in module memory only for the lifetime of the
 * tab. See organizer.ts for the full security invariants.
 */

import { hostedShell } from "./shell";
import { startManage, renderCredentialEntry, setManageExtensionRenderer } from "./organizer";
import { mountBrowserAnchorPanel } from "./browserAnchor";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = "";

const notice = `
  <div class="notice" role="note">
    <strong>Organizer console.</strong> You need the organizer secret created
    together with the election. It is not recoverable from the server.
  </div>`;

setManageExtensionRenderer(mountBrowserAnchorPanel);

renderCredentialEntry(
  (access) => {
    app.innerHTML = hostedShell(`<div class="card"><h2>Loading election…</h2></div>`, "manage");
    startManage(access);
  },
  notice
);
