import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { macosKeychain } from "../src/vault/custody.js";

// This test touches the real Keychain, so it is gated. Run with:
//   CHARADE_LIVE_KEYCHAIN=1 node --test dist/test/custody.live.test.js
const live = process.env.CHARADE_LIVE_KEYCHAIN === "1" && process.platform === "darwin";

describe("macOS Keychain live", { skip: live ? false : "set CHARADE_LIVE_KEYCHAIN=1" }, () => {
  it("stores, reads, and deletes a temporary generic password", () => {
    const service = `dev.floydslabs.charade.test.${process.pid}.${Date.now()}`;
    const account = "test-account";
    const secret = randomBytes(24).toString("base64url");
    const adapter = macosKeychain(undefined, service);
    try {
      adapter.set(account, Buffer.from(secret));
      assert.equal(adapter.get(account).toString(), secret);
    } finally {
      adapter.delete(account);
    }
    assert.throws(() => adapter.get(account));
  });
});
