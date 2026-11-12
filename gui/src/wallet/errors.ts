export type ProviderErrorCode =
  | 4001
  | 4100
  | 4200
  | -32601
  | -32603;

export function providerErrorCode(error: unknown): number | null {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === "number") {
      return code;
    }
  }
  return null;
}

export function providerErrorMessage(error: unknown): string {
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = (error as { message: unknown }).message;
    if (typeof message === "string" && message.length > 0) {
      return message;
    }
  }
  if (typeof error === "string") {
    return error;
  }
  return "";
}

export function describeProviderError(
  code: number | null,
  fallback: string,
): string {
  switch (code) {
    case 4001:
      return "The request was declined in the wallet.";
    case 4100:
      return "The wallet is available but not connected to this site yet. Approve the connection in the wallet first.";
    case 4200:
      return "The connected wallet does not support this operation.";
    case -32601:
      return "The connected wallet does not recognize this operation.";
    case -32603:
      return "The wallet reported an internal error.";
    default:
      return fallback;
  }
}
