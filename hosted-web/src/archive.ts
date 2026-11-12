import { hostedShell } from "./shell";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">Archive</h1>

  <p class="screen-lede">
    Inspect the public result and hosted archive information for an election.
  </p>

  <div class="notice" role="note">
    <strong>Hosted verification boundary.</strong>
    This page retrieves the ballot office's public result and archive data.
    Full offline archive replay verification remains available in the
    Private Ballot desktop application.
  </div>

  <section class="card">
    <div class="card-title">Election archive</div>

    <div class="form-row">
      <label for="archive-election-id">Election ID</label>
      <input
        id="archive-election-id"
        type="text"
        autocomplete="off"
        spellcheck="false"
        placeholder="Enter election ID"
      />
    </div>

    <div class="btn-row">
      <button id="load-results" class="btn btn-secondary" type="button">
        Load Results
      </button>

      <button id="load-archive" class="btn btn-primary" type="button">
        Load Archive
      </button>

      <button id="load-both" class="btn btn-secondary" type="button">
        Load Both
      </button>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Public result</div>
    <div id="results-status" class="form-hint">No result loaded.</div>
    <pre id="results-output" class="json-output"></pre>
  </section>

  <section class="card">
    <div class="card-title">Archive information</div>
    <div id="archive-status" class="form-hint">No archive loaded.</div>
    <pre id="archive-output" class="json-output"></pre>
  </section>
`, "archive");

function electionId(): string {
  return (
    document.getElementById("archive-election-id") as HTMLInputElement
  ).value.trim();
}

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

async function loadEndpoint(
  suffix: "results" | "archive",
  statusId: string,
  outputId: string,
): Promise<void> {
  const id = electionId();
  const status = document.getElementById(statusId) as HTMLElement;
  const output = document.getElementById(outputId) as HTMLElement;

  if (!id) {
    status.textContent = "Enter an election ID first.";
    output.textContent = "";
    return;
  }

  status.textContent = "Loading...";
  output.textContent = "";

  try {
    const response = await fetch(
      `/api/v1/elections/${encodeURIComponent(id)}/${suffix}`,
    );
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

document.getElementById("load-results")?.addEventListener("click", () => {
  void loadEndpoint("results", "results-status", "results-output");
});

document.getElementById("load-archive")?.addEventListener("click", () => {
  void loadEndpoint("archive", "archive-status", "archive-output");
});

document.getElementById("load-both")?.addEventListener("click", () => {
  void Promise.all([
    loadEndpoint("results", "results-status", "results-output"),
    loadEndpoint("archive", "archive-status", "archive-output"),
  ]);
});
