/**
 * Coordinates the native path picker with the Rust export command. The
 * frontend receives and forwards only a chosen path; Rust remains the sole
 * owner and writer of canonical ballot bytes.
 */

export class BallotSaveDialogError extends Error {
  constructor() {
    super("The native Save dialog could not open.");
    this.name = "BallotSaveDialogError";
  }
}

/**
 * @returns `false` when the voter cancels the native Save dialog; otherwise
 * resolves `true` only after the Rust export command has completed.
 */
export async function requestAndExportPreparedBallot(
  pickPath: () => Promise<string | null>,
  exportPreparedBallot: (path: string) => Promise<unknown>,
): Promise<boolean> {
  let path: string | null;
  try {
    path = await pickPath();
  } catch {
    throw new BallotSaveDialogError();
  }
  if (!path) return false;
  await exportPreparedBallot(path);
  return true;
}
