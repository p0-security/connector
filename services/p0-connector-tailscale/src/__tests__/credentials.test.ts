import { describe, expect, it } from "vitest";

import { tailnetCredentials } from "../credentials.ts";
import { AWS_SECRET, CREDENTIALS, TAILNET } from "./fixtures.ts";

const parse = (overrides: Record<string, unknown>) =>
  tailnetCredentials.safeParse({ ...CREDENTIALS, ...overrides });

describe("tailnetCredentials", () => {
  it.each([
    ["a Tailnet ID", TAILNET],
    ["the credential's own tailnet", "-"],
    ["a legacy domain ID", "example.com"],
    ["a legacy email ID", "alice@gmail.com"],
  ])("takes %s", (_case, tailnet) => {
    expect(parse({ tailnet }).success).toBe(true);
  });

  it.each([
    ["the tailnet's DNS name", "tail1234.ts.net"],
    ["a path", "T1234CNTRL/../other"],
    ["a dot segment", ".."],
    ["empty", ""],
    ["a query", "T1234?x=1"],
  ])("refuses %s as the tailnet", (_case, tailnet) => {
    expect(parse({ tailnet }).success).toBe(false);
  });

  it("takes a federated credential with no secret and no audience", () => {
    const parsed = parse({
      credential: { kind: "federated", clientId: "kAbc1CNTRL" },
    });
    expect(parsed.success && parsed.data.credential).toEqual({
      kind: "federated",
      clientId: "kAbc1CNTRL",
    });
  });

  it("takes an OAuth client whose secret is a pointer", () => {
    expect(
      parse({
        credential: {
          kind: "vault",
          clientId: "kAbc1CNTRL",
          secret: AWS_SECRET,
        },
      }).success
    ).toBe(true);
  });

  it("refuses the secret itself where the pointer goes", () => {
    expect(
      parse({
        credential: {
          kind: "vault",
          clientId: "kAbc1CNTRL",
          secret: "tskey-client-abc",
        },
      }).success
    ).toBe(false);
  });

  it("refuses a client ID that isn't one", () => {
    expect(
      parse({ credential: { kind: "federated", clientId: "a b" } }).success
    ).toBe(false);
  });
});
