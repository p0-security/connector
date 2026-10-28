import { describe, expect, it } from "vitest";

import { describeFailure, failureFacts } from "../failure.ts";

const failing = (fields: Record<string, unknown>, message = "secret-ish") =>
  Object.assign(new Error(message), fields);

describe("failureFacts", () => {
  it("keeps a failure's name, code, status and AWS request id, never its message", () => {
    const facts = failureFacts(
      failing({
        name: "ThrottlingException",
        code: "ECONNRESET",
        status: 429,
        $metadata: { requestId: "aws-req-1" },
      })
    );

    expect(facts).toStrictEqual({
      name: "ThrottlingException",
      code: "ECONNRESET",
      status: 429,
      requestId: "aws-req-1",
    });
    expect(JSON.stringify(facts)).not.toContain("secret-ish");
  });

  it("leaves out the bare `Error` name", () => {
    expect(failureFacts(new Error("x"))).toStrictEqual({});
  });

  it("keeps a numeric code", () => {
    expect(failureFacts(failing({ code: 7 }))).toStrictEqual({ code: 7 });
  });

  it("takes the status from AWS's metadata when the failure has none", () => {
    expect(
      failureFacts(failing({ $metadata: { httpStatusCode: 503 } }))
    ).toStrictEqual({ status: 503 });
  });

  it("prefers the failure's own status to AWS's", () => {
    expect(
      failureFacts(failing({ status: 401, $metadata: { httpStatusCode: 503 } }))
    ).toStrictEqual({ status: 401 });
  });

  it("reads a field of the wrong type as absent", () => {
    expect(
      failureFacts(
        failing({ name: 7, code: {}, status: "500", $metadata: "x" })
      )
    ).toStrictEqual({});
  });

  it.each([undefined, null, "a string", 42])(
    "says nothing about %j",
    (error) => {
      expect(failureFacts(error)).toStrictEqual({});
    }
  );
});

describe("describeFailure", () => {
  it("names a failure by its code and status", () => {
    expect(describeFailure(failing({ code: "ECONNRESET", status: 502 }))).toBe(
      "ECONNRESET, HTTP 502"
    );
  });

  it("names a failure by its name when its code isn't a string", () => {
    expect(describeFailure(failing({ name: "TimeoutError", code: 7 }))).toBe(
      "TimeoutError"
    );
  });

  it("names a failure by its status alone", () => {
    expect(describeFailure(failing({ status: 500 }))).toBe("HTTP 500");
  });

  it("says nothing about a failure that says nothing about itself", () => {
    expect(describeFailure(new Error("quiet"))).toBeUndefined();
  });
});
