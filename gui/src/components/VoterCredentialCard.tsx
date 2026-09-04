import { useEffect, useMemo, useState } from "react";

import {
  pickVoterCredentialBackupPath,
  pickVoterCredentialFile,
} from "../api/dialog";
import type {
  GuiCommandError,
  GuiSavedVoterCredentialsV1,
  GuiVoterCredentialStatusV1,
} from "../api/types";
import { createCredentialIsFutureElectionOnly } from "../voterTerminalState";
import {
  backupCredentialFlow,
  clearMemoryConfirmationText,
  copyPublicEnrollmentKey,
  createDurableCredentialFlow,
  CREDENTIAL_RECOVERY_WARNING,
  credentialEligibilityTone,
  credentialStorageText,
  defaultCredentialBackupFilename,
  deleteSavedCopyConfirmationText,
  importCredentialFlow,
  PASSPHRASE_MISMATCH_MESSAGE,
  publicKeyDisplay,
  unlockSavedCredentialFlow,
  WALLET_SEED_WARNING,
} from "../voterCredential";
import {
  BackendErrorNotice,
  Card,
  ConfirmDialog,
  Field,
  Notice,
  Pill,
} from "./ui";

type CredentialDialog = "create" | "unlock" | "import" | "backup";
type CredentialOperation =
  | "create"
  | "unlock"
  | "import"
  | "backup"
  | "clear"
  | "delete";
type ConfirmAction = "clear" | "delete";

export interface VoterCredentialCardProps {
  title?: string;
  status: GuiVoterCredentialStatusV1 | null;
  savedCredentials: GuiSavedVoterCredentialsV1 | null;
  shellAvailable: boolean;
  busy?: boolean;
  context: "vote" | "bootstrap";
  showFrozenElectionNotice?: boolean;
  /**
   * Optional election lifecycle. When the loaded election is already frozen (or
   * later), creating a NEW credential cannot make it eligible for that frozen
   * registry, so the Create-credential action is moved under a disclosure and
   * Unlock/Import remain primary/secondary. Omit for bootstrap contexts.
   */
  electionLifecycleState?: string | null;
  onCreate: (passphrase: string) => Promise<void>;
  onUnlock: (publicKeyHex: string, passphrase: string) => Promise<void>;
  onImport: (
    path: string,
    passphrase: string,
    persistLocally: boolean,
  ) => Promise<void>;
  onBackup: (path: string, passphrase: string) => Promise<void>;
  onClear: () => Promise<void>;
  onDeleteSaved: (publicKeyHex: string) => Promise<void>;
  onError: (error: unknown) => void;
  operationError?: GuiCommandError | null;
  onOperationSuccess?: () => void;
  onOperationErrorDismiss?: () => void;
}

export function VoterCredentialCard({
  title = "Your voter credential",
  status,
  savedCredentials,
  shellAvailable,
  busy = false,
  context,
  showFrozenElectionNotice = context === "vote",
  electionLifecycleState = null,
  onCreate,
  onUnlock,
  onImport,
  onBackup,
  onClear,
  onDeleteSaved,
  onError,
  operationError = null,
  onOperationSuccess,
  onOperationErrorDismiss,
}: VoterCredentialCardProps) {
  const saved = useMemo(
    () => savedCredentials?.credentials ?? [],
    [savedCredentials],
  );
  const [selectedPublicKey, setSelectedPublicKey] = useState("");
  const [dialog, setDialog] = useState<CredentialDialog | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirmation, setPassphraseConfirmation] = useState("");
  const [persistImport, setPersistImport] = useState(true);
  const [importPath, setImportPath] = useState<string | null>(null);
  const [backupPath, setBackupPath] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [operation, setOperation] = useState<CredentialOperation | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  const loaded = !!status?.credential_loaded;
  const createIsFutureOnly = createCredentialIsFutureElectionOnly(electionLifecycleState);
  const currentPublicKey = status?.public_governance_key_hex ?? null;
  const activeSavedCopy = !!currentPublicKey &&
    saved.some((credential) => credential.public_governance_key_hex === currentPublicKey);
  const selectedSavedCredential =
    saved.find((credential) => credential.public_governance_key_hex === selectedPublicKey) ??
    saved[0] ??
    null;
  const controlsBusy = busy || operation !== null;

  useEffect(() => {
    if (selectedSavedCredential) return;
    setSelectedPublicKey(saved[0]?.public_governance_key_hex ?? "");
  }, [saved, selectedSavedCredential]);

  useEffect(() => {
    return () => {
      resetPassphraseForm();
    };
  }, []);

  function resetPassphraseForm() {
    setPassphrase("");
    setPassphraseConfirmation("");
    setFormError(null);
  }

  function openDialog(next: CredentialDialog) {
    resetPassphraseForm();
    setSuccessNotice(null);
    setDialog(next);
  }

  function closeDialog() {
    resetPassphraseForm();
    setDialog(null);
    setImportPath(null);
    setBackupPath(null);
    setPersistImport(true);
  }

  function dialogError(code: string, message: string, contextLabel: string): GuiCommandError {
    return {
      code,
      category: "FILE_IO",
      context: contextLabel,
      message,
    };
  }

  async function runOperation(kind: CredentialOperation, fn: () => Promise<void>) {
    setOperation(kind);
    setFormError(null);
    setSuccessNotice(null);
    try {
      await fn();
      onOperationSuccess?.();
    } catch (error) {
      onError(error);
    } finally {
      setOperation(null);
    }
  }

  async function runDialogOperation(kind: CredentialOperation, fn: () => Promise<boolean>) {
    setOperation(kind);
    setFormError(null);
    setSuccessNotice(null);
    try {
      const finished = await fn();
      if (finished) {
        onOperationSuccess?.();
        closeDialog();
      }
    } catch (error) {
      onError(error);
    } finally {
      setOperation(null);
    }
  }

  async function openImportDialog() {
    try {
      const picked = await pickVoterCredentialFile();
      if (!picked) return;
      setImportPath(picked);
      setPersistImport(true);
      openDialog("import");
    } catch {
      onError(
        dialogError(
          "GUI_CREDENTIAL_OPEN_DIALOG_UNAVAILABLE",
          "The native Open dialog could not open for credential import.",
          "credential-import",
        ),
      );
    }
  }

  async function openBackupDialog() {
    try {
      const picked = await pickVoterCredentialBackupPath(defaultCredentialBackupFilename(status));
      if (!picked) return;
      setBackupPath(picked);
      openDialog("backup");
    } catch {
      onError(
        dialogError(
          "GUI_CREDENTIAL_SAVE_DIALOG_UNAVAILABLE",
          "The native Save dialog could not open for credential backup.",
          "credential-backup",
        ),
      );
    }
  }

  async function submitPassphraseDialog() {
    if (dialog === "create") {
      await runDialogOperation("create", async () => {
        const result = await createDurableCredentialFlow(
          passphrase,
          passphraseConfirmation,
          onCreate,
          resetPassphraseForm,
        );
        if (result === null) {
          setFormError(PASSPHRASE_MISMATCH_MESSAGE);
          return false;
        }
        setSuccessNotice("Credential created and loaded.");
        return true;
      });
      return;
    }

    if (dialog === "unlock" && selectedSavedCredential) {
      await runDialogOperation("unlock", async () => {
        await unlockSavedCredentialFlow(
          selectedSavedCredential.public_governance_key_hex,
          passphrase,
          onUnlock,
          resetPassphraseForm,
        );
        setSuccessNotice("Credential unlocked.");
        return true;
      });
      return;
    }

    if (dialog === "import" && importPath) {
      await runDialogOperation("import", async () => {
        await importCredentialFlow(
          importPath,
          passphrase,
          persistImport,
          onImport,
          resetPassphraseForm,
        );
        setSuccessNotice(
          persistImport
            ? "Credential imported and saved locally."
            : "Credential imported for this app session only.",
        );
        return true;
      });
      return;
    }

    if (dialog === "backup" && backupPath) {
      await runDialogOperation("backup", async () => {
        const result = await backupCredentialFlow(
          backupPath,
          passphrase,
          passphraseConfirmation,
          onBackup,
          resetPassphraseForm,
        );
        if (result === null) {
          setFormError(PASSPHRASE_MISMATCH_MESSAGE);
          return false;
        }
        setSuccessNotice("Encrypted credential backup written.");
        return true;
      });
    }
  }

  async function copyPublicKey() {
    try {
      const copied = await copyPublicEnrollmentKey(
        status,
        (value) => navigator.clipboard.writeText(value),
      );
      if (!copied) return;
      setCopyNotice("Public enrollment key copied.");
      window.setTimeout(() => setCopyNotice(null), 1800);
    } catch {
      setCopyNotice(null);
    }
  }

  async function confirmClear() {
    setConfirmAction(null);
    await runOperation("clear", onClear);
  }

  async function confirmDelete() {
    if (!currentPublicKey) return;
    setConfirmAction(null);
    await runOperation("delete", () => onDeleteSaved(currentPublicKey));
  }

  return (
    <>
      <Card title={title}>
        <Notice tone="warn">{WALLET_SEED_WARNING}</Notice>
        {showFrozenElectionNotice && (
          <p className="form-hint">
            Creating a new credential after this election was frozen cannot add it to the
            registry. Use the credential whose public enrollment key the organizer enrolled.
          </p>
        )}
        {successNotice && <Notice tone="ok">{successNotice}</Notice>}
        <BackendErrorNotice
          error={operationError}
          onDismiss={onOperationErrorDismiss}
        />

        {loaded ? (
          <LoadedCredential
            status={status}
            activeSavedCopy={activeSavedCopy}
            controlsBusy={controlsBusy}
            copyNotice={copyNotice}
            onCopyPublicKey={copyPublicKey}
            onBackup={() => void openBackupDialog()}
            onClear={() => setConfirmAction("clear")}
            onDeleteSaved={() => setConfirmAction("delete")}
          />
        ) : saved.length > 0 ? (
          <SavedCredentialUnlock
            savedCredentials={savedCredentials}
            selectedPublicKey={selectedSavedCredential?.public_governance_key_hex ?? ""}
            controlsBusy={controlsBusy}
            shellAvailable={shellAvailable}
            createIsFutureOnly={createIsFutureOnly}
            onSelectPublicKey={setSelectedPublicKey}
            onUnlock={() => openDialog("unlock")}
            onImport={() => void openImportDialog()}
            onCreate={() => openDialog("create")}
          />
        ) : (
          <NoCredential
            controlsBusy={controlsBusy}
            shellAvailable={shellAvailable}
            createIsFutureOnly={createIsFutureOnly}
            onCreate={() => openDialog("create")}
            onImport={() => void openImportDialog()}
          />
        )}
      </Card>

      {dialog && (
        <PassphraseDialog
          dialog={dialog}
          busy={controlsBusy}
          passphrase={passphrase}
          passphraseConfirmation={passphraseConfirmation}
          persistImport={persistImport}
          formError={formError}
          onPassphraseChange={setPassphrase}
          onPassphraseConfirmationChange={setPassphraseConfirmation}
          onPersistImportChange={setPersistImport}
          onSubmit={() => void submitPassphraseDialog()}
          onCancel={closeDialog}
        />
      )}

      {confirmAction === "clear" && (
        <ConfirmDialog
          title="Clear from memory?"
          body={<p>{clearMemoryConfirmationText(status, activeSavedCopy)}</p>}
          confirmLabel="Clear from memory"
          confirmTone={activeSavedCopy ? "primary" : "danger"}
          busy={controlsBusy}
          onConfirm={() => void confirmClear()}
          onCancel={() => setConfirmAction(null)}
        />
      )}

      {confirmAction === "delete" && (
        <ConfirmDialog
          title="Delete saved copy?"
          body={<p>{deleteSavedCopyConfirmationText(status)}</p>}
          confirmLabel="Delete saved copy"
          confirmTone="danger"
          busy={controlsBusy}
          onConfirm={() => void confirmDelete()}
          onCancel={() => setConfirmAction(null)}
        />
      )}
    </>
  );
}

function NoCredential({
  controlsBusy,
  shellAvailable,
  createIsFutureOnly,
  onCreate,
  onImport,
}: {
  controlsBusy: boolean;
  shellAvailable: boolean;
  createIsFutureOnly: boolean;
  onCreate: () => void;
  onImport: () => void;
}) {
  if (createIsFutureOnly) {
    // The loaded election is already frozen (or later): a NEW credential cannot
    // be enrolled into that frozen registry, so Import is the only path that
    // can lead to eligibility for THIS election. Creation is retained under a
    // "for a future election" disclosure.
    return (
      <>
        <p className="form-hint">{CREDENTIAL_RECOVERY_WARNING}</p>
        <div className="action-row">
          <button
            type="button"
            className="btn btn-primary"
            disabled={controlsBusy || !shellAvailable}
            onClick={onImport}
          >
            Import credential
          </button>
        </div>
        <details className="future-election">
          <summary>For a future election</summary>
          <p className="form-hint">
            A newly created credential cannot make you eligible for this already-frozen
            election unless its public enrollment key was enrolled before freeze.
          </p>
          <div className="action-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={controlsBusy || !shellAvailable}
              onClick={onCreate}
            >
              Create credential
            </button>
          </div>
        </details>
      </>
    );
  }
  return (
    <>
      <p className="form-hint">{CREDENTIAL_RECOVERY_WARNING}</p>
      <div className="action-row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={controlsBusy || !shellAvailable}
          onClick={onCreate}
        >
          Create credential
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={controlsBusy || !shellAvailable}
          onClick={onImport}
        >
          Import credential
        </button>
      </div>
    </>
  );
}

function SavedCredentialUnlock({
  savedCredentials,
  selectedPublicKey,
  controlsBusy,
  shellAvailable,
  createIsFutureOnly,
  onSelectPublicKey,
  onUnlock,
  onImport,
  onCreate,
}: {
  savedCredentials: GuiSavedVoterCredentialsV1 | null;
  selectedPublicKey: string;
  controlsBusy: boolean;
  shellAvailable: boolean;
  createIsFutureOnly: boolean;
  onSelectPublicKey: (publicKeyHex: string) => void;
  onUnlock: () => void;
  onImport: () => void;
  onCreate: () => void;
}) {
  const saved = savedCredentials?.credentials ?? [];
  const selected = saved.find((item) => item.public_governance_key_hex === selectedPublicKey) ??
    saved[0] ??
    null;
  return (
    <>
      <p className="form-hint">
        A saved encrypted credential exists on this computer. Unlock it with its passphrase to
        use the same public enrollment key after restart.
      </p>
      <div className="field-list">
        <Field label={saved.length > 1 ? "Saved credentials" : "Saved credential"}>
          {saved.length > 1 ? (
            <select
              className="text-input"
              value={selected?.public_governance_key_hex ?? ""}
              disabled={controlsBusy}
              onChange={(event) => onSelectPublicKey(event.target.value)}
            >
              {saved.map((credential) => (
                <option
                  key={credential.public_governance_key_hex}
                  value={credential.public_governance_key_hex}
                >
                  {credential.public_governance_key_abbrev}
                </option>
              ))}
            </select>
          ) : (
            <span className="field-value">
              {selected?.public_governance_key_abbrev ?? "Saved credential"}
            </span>
          )}
        </Field>
        {savedCredentials && savedCredentials.skipped_invalid_count > 0 && (
          <Field label="Skipped files">
            <span className="field-value">
              {savedCredentials.skipped_invalid_count} invalid credential file
              {savedCredentials.skipped_invalid_count === 1 ? "" : "s"} ignored
            </span>
          </Field>
        )}
      </div>
      <div className="action-row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={controlsBusy || !shellAvailable || !selected}
          onClick={onUnlock}
        >
          Unlock saved credential
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={controlsBusy || !shellAvailable}
          onClick={onImport}
        >
          Import credential
        </button>
        {!createIsFutureOnly && (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={controlsBusy || !shellAvailable}
            onClick={onCreate}
          >
            Create credential
          </button>
        )}
      </div>
      {createIsFutureOnly && (
        <details className="future-election">
          <summary>For a future election</summary>
          <p className="form-hint">
            A newly created credential cannot make you eligible for this already-frozen
            election unless its public enrollment key was enrolled before freeze.
          </p>
          <div className="action-row">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={controlsBusy || !shellAvailable}
              onClick={onCreate}
            >
              Create credential
            </button>
          </div>
        </details>
      )}
    </>
  );
}

function LoadedCredential({
  status,
  activeSavedCopy,
  controlsBusy,
  copyNotice,
  onCopyPublicKey,
  onBackup,
  onClear,
  onDeleteSaved,
}: {
  status: GuiVoterCredentialStatusV1 | null;
  activeSavedCopy: boolean;
  controlsBusy: boolean;
  copyNotice: string | null;
  onCopyPublicKey: () => void;
  onBackup: () => void;
  onClear: () => void;
  onDeleteSaved: () => void;
}) {
  const eligibilityTone = credentialEligibilityTone(status?.eligibility ?? "NotChecked");
  return (
    <>
      <div className="field-list">
        <Field label="Credential">
          <Pill tone="ok">Credential loaded</Pill>
        </Field>
        <Field label="Public enrollment key">
          <span className="field-value">{publicKeyDisplay(status)}</span>
          <button
            type="button"
            className="btn btn-secondary btn-copy"
            disabled={controlsBusy || !status?.public_governance_key_hex}
            onClick={() => void onCopyPublicKey()}
          >
            Copy public key
          </button>
        </Field>
        <Field label="Eligibility">
          <Pill tone={eligibilityTone}>
            {status?.eligibility_label ?? "No credential loaded"}
          </Pill>
        </Field>
        <Field label="Storage">
          <span className="field-value">{credentialStorageText(status)}</span>
        </Field>
      </div>
      {copyNotice && <Notice tone="ok">{copyNotice}</Notice>}
      {status?.session_only && (
        <Notice tone="warn">{credentialStorageText(status)}</Notice>
      )}
      <p className="form-hint">
        Back up credential creates another encrypted copy. Your saved credential on this
        computer is unchanged.
      </p>
      <div className="action-row">
        <button
          type="button"
          className="btn btn-secondary"
          disabled={controlsBusy}
          onClick={onBackup}
        >
          Back up credential
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={controlsBusy}
          onClick={onClear}
        >
          Clear from memory
        </button>
        {activeSavedCopy && (
          <button
            type="button"
            className="btn btn-danger"
            disabled={controlsBusy}
            onClick={onDeleteSaved}
          >
            Delete saved copy
          </button>
        )}
      </div>
    </>
  );
}

function PassphraseDialog({
  dialog,
  busy,
  passphrase,
  passphraseConfirmation,
  persistImport,
  formError,
  onPassphraseChange,
  onPassphraseConfirmationChange,
  onPersistImportChange,
  onSubmit,
  onCancel,
}: {
  dialog: CredentialDialog;
  busy: boolean;
  passphrase: string;
  passphraseConfirmation: string;
  persistImport: boolean;
  formError: string | null;
  onPassphraseChange: (value: string) => void;
  onPassphraseConfirmationChange: (value: string) => void;
  onPersistImportChange: (value: boolean) => void;
  onSubmit: () => void;
  onCancel: () => void;
}) {
  const needsConfirmation = dialog === "create" || dialog === "backup";
  const title =
    dialog === "create"
      ? "Create credential"
      : dialog === "unlock"
        ? "Unlock saved credential"
        : dialog === "import"
          ? "Import credential"
          : "Back up credential";
  const confirmLabel =
    dialog === "create"
      ? "Create credential"
      : dialog === "unlock"
        ? "Unlock"
        : dialog === "import"
          ? "Import"
          : "Back up";

  // Native form semantics so pressing Enter in the passphrase field submits via
  // the SAME handler as the button (Failure 6). preventDefault stops the webview
  // from navigating; the submit is gated by the same disabled condition as the
  // button (busy or empty passphrase), so a disabled state also blocks Enter and
  // no duplicate invocation occurs.
  const canSubmit = !busy && passphrase.length > 0;
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label={title}>
      <form
        className="modal"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSubmit) onSubmit();
        }}
      >
        <h3 className="modal-title">{title}</h3>
        <div className="modal-body">
          {dialog === "backup" && (
            <p className="form-hint">
              This creates another encrypted copy. Your saved credential on this computer is
              unchanged.
            </p>
          )}
          <div className="form-row">
            <label htmlFor="credential-passphrase">Passphrase</label>
            <input
              id="credential-passphrase"
              className="text-input"
              type="password"
              value={passphrase}
              autoComplete={needsConfirmation ? "new-password" : "current-password"}
              onChange={(event) => onPassphraseChange(event.target.value)}
            />
          </div>
          {needsConfirmation && (
            <div className="form-row">
              <label htmlFor="credential-passphrase-confirmation">
                Confirm passphrase
              </label>
              <input
                id="credential-passphrase-confirmation"
                className="text-input"
                type="password"
                value={passphraseConfirmation}
                autoComplete="new-password"
                onChange={(event) =>
                  onPassphraseConfirmationChange(event.target.value)
                }
              />
            </div>
          )}
          {dialog === "import" && (
            <label className="radio-option">
              <input
                type="checkbox"
                checked={persistImport}
                onChange={(event) => onPersistImportChange(event.target.checked)}
              />
              Save an encrypted copy on this computer
            </label>
          )}
          {formError && <Notice tone="warn">{formError}</Notice>}
        </div>
        <div className="modal-actions">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!canSubmit}
          >
            {confirmLabel}
          </button>
        </div>
      </form>
    </div>
  );
}
