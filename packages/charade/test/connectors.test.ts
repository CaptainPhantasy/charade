import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { classifyAction, injectAuth } from "../src/broker/connectors.js";
import type { ServiceRecord } from "../src/registry/registry.js";

function service(overrides: Partial<ServiceRecord> = {}): ServiceRecord {
  return {
    id: "svc",
    name: "Service",
    url: "https://example.test",
    transport: "http",
    auth: { type: "header", name: "Authorization", template: "Bearer ${SVC_KEY}" },
    actions: {
      read: ["GET /v1/*"],
      write: ["POST /v1/*"],
      destructive: ["send POST /send"],
    },
    ...overrides,
  };
}

describe("connectors", () => {
  it("injects a header template without forwarding the client token", () => {
    const result = injectAuth(service(), "secret-value", { authorization: "Bearer session" }, new URL("https://example.test"));
    assert.equal(result.headers.Authorization, "Bearer secret-value");
    assert.equal(result.headers["x-charade-lease"], undefined);
  });

  it("injects basic and query credentials", () => {
    const basic = injectAuth(
      service({ auth: { type: "basic" } }),
      "user:pass",
      {},
      new URL("https://example.test"),
    );
    assert.equal(basic.headers.Authorization, `Basic ${Buffer.from("user:pass").toString("base64")}`);
    const query = injectAuth(
      service({ auth: { type: "query", name: "api_key" } }),
      "secret-value",
      {},
      new URL("https://example.test/v1?x=1"),
    );
    assert.equal(query.url.searchParams.get("api_key"), "secret-value");
    assert.equal(query.url.searchParams.get("x"), "1");
  });

  it("classifies read, write, destructive, and unknown actions", () => {
    assert.equal(classifyAction(service(), "GET", "/v1/echo").class, "read");
    assert.equal(classifyAction(service(), "POST", "/v1/echo").class, "write");
    const destructive = classifyAction(service(), "POST", "/send");
    assert.equal(destructive.class, "destructive");
    assert.equal(destructive.stop, "send");
    assert.equal(classifyAction(service(), "DELETE", "/v1/echo").class, "unknown");
    assert.equal(classifyAction(service(), "GET", "/outside").class, "unknown");
  });
});
