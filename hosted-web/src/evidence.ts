import { hostedShell } from "./shell";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">Evidence</h1>

  <p class="screen-lede">
    Inspect public election evidence, organizer receipts, and optional
    Tari Ootle anchor status.
  </p>

  <div class="notice" role="note">
    <strong>Evidence is not the ballot.</strong>
    Receipts and anchor records describe acceptance and public commitments.
    Individual voter credentials, anonymous eligibility proofs, and private
    ballot contents are not published here.
  </div>

  <section class="card">
    <div class="card-title">Election evidence</div>

    <div class="form-row">
      <label for="evidence-election-id">Election ID</label>
      <input
        id="evidence-election-id"
        type="text"
        autocomplete="off"
        spellcheck="false"
        placeholder="Enter election ID"
      />
    </div>

    <div class="btn-row">
      <button id="load-ootle" class="btn btn-primary" type="button">
        Check Ootle Status
      </button>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Ootle anchor status</div>
    <div id="ootle-status" class="form-hint">
      No anchor status loaded.
    </div>
    <pre id="ootle-output" class="json-output"></pre>
  </section>

  <section class="card">
    <div class="card-title">Organizer receipt</div>

    <div class="form-row">
      <label for="evidence-receipt-id">Receipt ID</label>
      <input
        id="evidence-receipt-id"
        type="text"
        autocomplete="off"
        spellcheck="false"
        placeholder="Enter receipt ID"
      />
    </div>

    <div class="btn-row">
      <button id="load-receipt" class="btn btn-secondary" type="button">
        Load Receipt
      </button>
    </div>

    <div id="receipt-status" class="form-hint">
      No receipt loaded.
    </div>
    <pre id="receipt-output" class="json-output"></pre>
  </section>
`, "evidence");

function value(id: string): string {
  return (document.getElementById(id) as HTMLInputElement).value.trim();
}

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

async function fetchInto(
  url: string,
  statusId: string,
  outputId: string,
): Promise<void> {
  const status = document.getElementById(statusId) as HTMLElement;
  const output = document.getElementById(outputId) as HTMLElement;

  status.textContent = "Loading...";
  output.textContent = "";

  try {
    const response = await fetch(url);
    const body = await response.text();

    status.textContent = response.ok
      ? `${response.status} · loaded`
      : `${response.status} · request failed`;

    output.textContent = pretty(body);
  } catch {
    status.textContent = "Network request failed.";
    output.textContent = "";
  }
}

document.getElementById("load-ootle")?.addEventListener("click", () => {
  const id = value("evidence-election-id");

  if (!id) {
    (document.getElementById("ootle-status") as HTMLElement).textContent =
      "Enter an election ID first.";
    return;
  }

  void fetchInto(
    `/api/v1/elections/${encodeURIComponent(id)}/ootle-status`,
    "ootle-status",
    "ootle-output",
  );
});

document.getElementById("load-receipt")?.addEventListener("click", () => {
  const electionId = value("evidence-election-id");
  const receiptId = value("evidence-receipt-id");

  if (!electionId || !receiptId) {
    (document.getElementById("receipt-status") as HTMLElement).textContent =
      "Enter both an election ID and receipt ID.";
    return;
  }

  void fetchInto(
    `/api/v1/elections/${encodeURIComponent(electionId)}/receipt/${encodeURIComponent(receiptId)}`,
    "receipt-status",
    "receipt-output",
  );
});
