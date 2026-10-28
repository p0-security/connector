import { describe, expect, it } from "vitest";

import { schema } from "../definition.ts";

const MEMBER =
  "principal://iam.googleapis.com/projects/123456789/locations/global/" +
  "workloadIdentityPools/p0-pool/subject/agentic-identity/0123456789abcdef";

describe("agentic identity wire schema", () => {
  it("carries everything createUser needs in the user body", () => {
    expect(
      schema.userBody.safeParse({
        project: "customer-identities",
        accountId: "p0a-agile-otter-1f2e3d4c",
        subject: "agentic-identity/0123456789abcdef",
      }).success
    ).toBe(true);
    expect(
      schema.userBody.safeParse({
        project: "customer-identities",
        subject: "agentic-identity/0123456789abcdef",
      }).success
    ).toBe(false);
  });

  it("requires a member on every policy", () => {
    expect(schema.policy.safeParse({ member: MEMBER }).success).toBe(true);
    expect(
      schema.policy.safeParse({ expiresAt: "2026-02-02T00:00:00Z" }).success
    ).toBe(false);
  });

  // The perimeter re-checks this before it reaches CEL; refusing it on the
  // wire as well means a malformed value never reaches the primitives at all.
  it("refuses an expiry that is not an instant", () => {
    expect(
      schema.policy.safeParse({
        member: MEMBER,
        expiresAt: '2026-02-02T00:00:00Z") || true || ("',
      }).success
    ).toBe(false);
  });

  it("keeps the request context to the id and the project", () => {
    expect(
      schema.requestContext.parse({
        requestId: "r",
        project: "customer-identities",
        accountId: "ignored",
      })
    ).toEqual({ requestId: "r", project: "customer-identities" });
  });
});
