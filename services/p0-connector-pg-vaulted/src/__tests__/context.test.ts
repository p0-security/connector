import { describe, expect, it } from "vitest";

import {
  GRANT_LOGIN_PATTERN,
  GRANT_SECRET_NAME_PATTERN,
  isGrantSecretOfLogin,
  requestContext,
} from "../context.ts";
import { GRANT_KEY, LOGIN, context } from "./fixtures.ts";

describe("GRANT_LOGIN_PATTERN", () => {
  it("matches p0v_ and a 32-digit lowercase hex grant key", () => {
    expect(GRANT_LOGIN_PATTERN.test(LOGIN)).toBe(true);
  });

  it.each([
    "postgres",
    GRANT_KEY,
    "p0v_",
    `p0v_${GRANT_KEY.slice(1)}`,
    `p0v_${GRANT_KEY}0`,
    `p0v_${GRANT_KEY.toUpperCase()}`,
    `P0V_${GRANT_KEY}`,
    `p0v_${GRANT_KEY.slice(1)}g`,
    `p0v_${GRANT_KEY}"`,
    ` ${LOGIN}`,
    `${LOGIN}\n`,
  ])("refuses %j", (login) => {
    expect(GRANT_LOGIN_PATTERN.test(login)).toBe(false);
  });
});

describe("GRANT_SECRET_NAME_PATTERN", () => {
  it.each([
    `p0/postgres-ai/vpc-0a1b2c3d/t/${LOGIN}`,
    `p0/postgres-ai/vpc-0a1b2c3d4e5f67890/Orders-Prod-1/${LOGIN}`,
    `p0/postgres-ai/vpc-0a1b2c3d/${"t".repeat(63)}/${LOGIN}`,
  ])("matches %j", (secretName) => {
    expect(GRANT_SECRET_NAME_PATTERN.test(secretName)).toBe(true);
  });
});

describe("request context", () => {
  it("accepts a context, unchanged", () => {
    expect(requestContext.parse(context)).toEqual(context);
  });

  it.each([
    ["outside the prefix", `p0/access-token/vpc-0a1b2c3d/orders/${LOGIN}`],
    ["under a longer prefix", `x/p0/postgres-ai/vpc-0a1b2c3d/orders/${LOGIN}`],
    ["with no vpc id", `p0/postgres-ai/orders/${LOGIN}`],
    ["with a short vpc id", `p0/postgres-ai/vpc-0a1b2c3/orders/${LOGIN}`],
    [
      "with a long vpc id",
      `p0/postgres-ai/vpc-0a1b2c3d4e5f678901/orders/${LOGIN}`,
    ],
    [
      "with an upper-case vpc id",
      `p0/postgres-ai/vpc-0A1B2C3D/orders/${LOGIN}`,
    ],
    [
      "with a vpc id that is not hex",
      `p0/postgres-ai/vpc-wxyz0123/orders/${LOGIN}`,
    ],
    ["with no target id", `p0/postgres-ai/vpc-0a1b2c3d/${LOGIN}`],
    ["with an empty target id", `p0/postgres-ai/vpc-0a1b2c3d//${LOGIN}`],
    [
      "with a target id that starts with a hyphen",
      `p0/postgres-ai/vpc-0a1b2c3d/-orders/${LOGIN}`,
    ],
    [
      "with a long target id",
      `p0/postgres-ai/vpc-0a1b2c3d/${"t".repeat(64)}/${LOGIN}`,
    ],
    [
      "with a nested target id",
      `p0/postgres-ai/vpc-0a1b2c3d/orders/prod/${LOGIN}`,
    ],
    ["with no login", "p0/postgres-ai/vpc-0a1b2c3d/orders"],
    ["with an empty login", "p0/postgres-ai/vpc-0a1b2c3d/orders/"],
    [
      "with a login outside the namespace",
      "p0/postgres-ai/vpc-0a1b2c3d/orders/postgres",
    ],
    [
      "with a path after the login",
      `p0/postgres-ai/vpc-0a1b2c3d/orders/${LOGIN}/x`,
    ],
  ])("refuses a secret name %s", (_reason, secretName) => {
    expect(requestContext.safeParse({ ...context, secretName }).success).toBe(
      false
    );
  });

  it("accepts a deadline in the past", () => {
    const deadline = "2001-01-01T00:00:00Z";

    expect(requestContext.parse({ ...context, deadline }).deadline).toBe(
      deadline
    );
  });

  it("accepts a deadline with an offset", () => {
    const deadline = "2026-12-01T02:00:00+02:00";

    expect(requestContext.parse({ ...context, deadline }).deadline).toBe(
      deadline
    );
  });

  it.each(["", "tomorrow", "2026-12-01", "2026-12-01T00:00:00", "1796083200"])(
    "refuses the deadline %j",
    (deadline) => {
      expect(requestContext.safeParse({ ...context, deadline }).success).toBe(
        false
      );
    }
  );

  it("truncates a long comment", () => {
    const parsed = requestContext.parse({
      ...context,
      comment: "x".repeat(5000),
    });

    expect(parsed.comment).toBe("x".repeat(1000));
  });

  it("coerces a port sent as a string", () => {
    const parsed = requestContext.parse({
      ...context,
      target: { ...context.target, port: "5433" },
    });

    expect(parsed.target.port).toBe(5433);
  });

  it.each([0, 65536, 5432.5, "postgres"])("refuses the port %j", (port) => {
    expect(
      requestContext.safeParse({
        ...context,
        target: { ...context.target, port },
      }).success
    ).toBe(false);
  });

  it.each([
    { requestId: "" },
    { target: { ...context.target, host: "" } },
    { target: { ...context.target, database: "" } },
    { secrets: { manager: "aws", region: "" } },
    { secrets: { manager: "aws", region: "us-east-1.attacker.example" } },
    { secrets: { manager: "gcp", projectId: "proj" } },
  ])("refuses the request context %j", (override) => {
    expect(requestContext.safeParse({ ...context, ...override }).success).toBe(
      false
    );
  });
});

describe("isGrantSecretOfLogin", () => {
  it("accepts the secret named for the login", () => {
    expect(isGrantSecretOfLogin(context.secretName, LOGIN)).toBe(true);
  });

  it("refuses the secret named for another login", () => {
    const other = `p0v_${"f".repeat(32)}`;

    expect(isGrantSecretOfLogin(context.secretName, other)).toBe(false);
  });

  it("refuses a login that is only the end of the secret's last segment", () => {
    expect(isGrantSecretOfLogin(context.secretName, GRANT_KEY)).toBe(false);
  });
});
