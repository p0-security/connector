import { describe, expect, it } from "vitest";

import { installContext, requestContext } from "../context.ts";

const context = {
  requestId: "r1",
  secrets: { manager: "aws", region: "us-west-2" },
  instance: { id: "i-0123456789abcdef0", region: "us-east-1" },
};

describe("requestContext", () => {
  it("accepts a request for one instance", () => {
    expect(requestContext.parse(context)).toEqual(context);
  });

  it("accepts an instance id from before 2016", () => {
    const instance = { ...context.instance, id: "i-1a2b3c4d" };
    expect(requestContext.safeParse({ ...context, instance }).success).toBe(
      true
    );
  });

  it.each([
    ["an empty request id", { requestId: "" }],
    [
      "a vault outside AWS",
      { secrets: { manager: "gcp", region: "us-west-2" } },
    ],
    [
      "a vault region that isn't one",
      { secrets: { manager: "aws", region: "example.com/x" } },
    ],
    [
      "an instance id that isn't one",
      { instance: { id: "i-0123; rm -rf /", region: "us-east-1" } },
    ],
    [
      "a managed node that isn't an EC2 instance",
      { instance: { id: "mi-0123456789abcdef0", region: "us-east-1" } },
    ],
    [
      "an instance region that isn't one",
      { instance: { id: "i-0123456789abcdef0", region: "US-EAST-1" } },
    ],
  ])("refuses %s", (_name, change) => {
    expect(requestContext.safeParse({ ...context, ...change }).success).toBe(
      false
    );
  });
});

describe("installContext", () => {
  it("accepts a region", () => {
    expect(installContext.parse({ region: "eu-central-1" })).toEqual({
      region: "eu-central-1",
    });
  });

  it("refuses a region that isn't one", () => {
    expect(installContext.safeParse({ region: "eu" }).success).toBe(false);
  });
});
