import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  describeProviderError,
  providerErrorCode,
  providerErrorMessage,
} from "../src/wallet/errors.ts";
import { WalletProviderError } from "../src/wallet/provider.ts";

describe("provider error extraction", () => {
  it("reads the numeric code from a provider rejection", () => {
    assert.equal(providerErrorCode({ code: 4100 }), 4100);
    assert.equal(providerErrorCode({ code: -32603, message: "boom" }), -32603);
  });

  it("returns null for missing or non-numeric codes", () => {
    assert.equal(providerErrorCode(new Error("boom")), null);
    assert.equal(providerErrorCode({ code: "4100" }), null);
    assert.equal(providerErrorCode(null), null);
    assert.equal(providerErrorCode("declined"), null);
  });

  it("reads provider messages and returns empty without one", () => {
    assert.equal(providerErrorMessage({ message: "boom" }), "boom");
    assert.equal(providerErrorMessage({ code: 4100 }), "");
    assert.equal(providerErrorMessage(new Error("native")), "native");
    assert.equal(providerErrorMessage("declined"), "declined");
    assert.equal(providerErrorMessage(null), "");
  });
});

describe("provider error taxonomy", () => {
  it("gives every known provider code a bounded human label", () => {
    assert.match(describeProviderError(4001, "raw"), /declined in the wallet/);
    assert.match(describeProviderError(4100, "raw"), /not connected to this site yet/);
    assert.match(describeProviderError(4200, "raw"), /does not support this operation/);
    assert.match(describeProviderError(-32601, "raw"), /does not recognize this operation/);
    assert.match(describeProviderError(-32603, "raw"), /internal error/);
  });

  it("falls back to the raw detail for unknown codes", () => {
    assert.equal(describeProviderError(null, "raw"), "raw");
    assert.equal(describeProviderError(1234, "raw"), "raw");
  });
});

describe("WalletProviderError", () => {
  it("carries the provider code through", () => {
    const error = new WalletProviderError("message", 4001);
    assert.equal(error.code, 4001);
    assert.equal(error.name, "WalletProviderError");
    assert.equal(providerErrorCode(error), 4001);
    assert.equal(providerErrorMessage(error), "message");
  });
});
