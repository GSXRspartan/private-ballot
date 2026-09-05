import { invoke } from "@tauri-apps/api/core";

export interface CommandError {
  code: string;
  category: string;
  context: string | null;
  message: string;
}

export class BackendError extends Error {
  readonly payload: CommandError;

  constructor(payload: CommandError) {
    super(payload.message);
    this.name = "BackendError";
    this.payload = payload;
  }
}

function asBackendError(error: unknown): BackendError {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "category" in error &&
    "message" in error
  ) {
    return new BackendError(error as CommandError);
  }
  return new BackendError({
    code: "LOAD_TESTER_FRONTEND_BOUNDARY",
    category: "INVALID_INPUT",
    context: null,
    message: "the load tester backend is unavailable",
  });
}

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw asBackendError(error);
  }
}
