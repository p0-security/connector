import { describe, expect, it } from "vitest";

import { describeFailure, failureFacts } from "../failure.ts";

describe("failureFacts", () => {
  // `toStrictEqual`, because a fact it doesn't have must be absent, not an
  // `undefined` key that a log line would print.
  it.each([
    ["a bare Error", new Error("secret-id"), {}],
    [
      "a named error",
      Object.assign(new Error("x"), { name: "ThrottlingException" }),
      { name: "ThrottlingException" },
    ],
    [
      "a code alone",
      Object.assign(new Error("x"), { code: "ENOTFOUND" }),
      { code: "ENOTFOUND" },
    ],
    [
      "a status alone",
      Object.assign(new Error("x"), { status: 503 }),
      { status: 503 },
    ],
    [
      "AWS's metadata",
      Object.assign(new Error("x"), {
        $metadata: { httpStatusCode: 400, requestId: "req-1" },
      }),
      { status: 400, requestId: "req-1" },
    ],
    [
      "fields of the wrong type",
      Object.assign(new Error("x"), { code: { nested: true }, status: "500" }),
      {},
    ],
    // Google's client throws plain objects too, with no name at all.
    ["an object with a code and no name", { code: 7 }, { code: 7 }],
    ["something that isn't an error", "secret-id", {}],
  ])("keeps only what %s says of itself", (_case, error, facts) => {
    expect(failureFacts(error)).toStrictEqual(facts);
  });
});

describe("describeFailure", () => {
  it("names the code and the status", () => {
    expect(
      describeFailure(
        Object.assign(new Error("x"), { code: "ECONNRESET", status: 502 })
      )
    ).toBe("ECONNRESET, HTTP 502");
  });

  it("says nothing for a failure that says nothing", () => {
    expect(describeFailure(new Error("secret-id"))).toBeUndefined();
  });
});
