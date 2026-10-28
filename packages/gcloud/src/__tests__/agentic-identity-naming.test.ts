import { describe, expect, it } from "vitest";

import {
  agenticIdentityEmail,
  isAgenticIdentityAccountId,
  isAgenticIdentityEmail,
  isAgenticIdentitySubject,
  parseWorkloadIdentityPrincipal,
} from "../agentic-identity/naming.ts";

const ACCOUNT_ID = "p0a-agile-otter-1f2e3d4c";

describe("agentic identity naming", () => {
  it("accepts only p0a-, two lowercase words and eight hex characters", () => {
    expect(isAgenticIdentityAccountId(ACCOUNT_ID)).toBe(true);
    expect(isAgenticIdentityAccountId("p0a-agile-otter-1f2e3d4")).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-agile-otter-1f2e3d4c0")).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-agile-otter-1F2E3D4C")).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-Agile-otter-1f2e3d4c")).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-agile-1f2e3d4c")).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-agile-sea-otter-1f2e3d4c")).toBe(
      false
    );
    expect(isAgenticIdentityAccountId("p0-agile-otter-1f2e3d4c")).toBe(false);
    expect(isAgenticIdentityAccountId(`x${ACCOUNT_ID}`)).toBe(false);
  });

  // The previous, session-derived shape: addresses it named were re-created
  // when a session granted again, so the guard no longer admits it.
  it("refuses the old session-derived shape", () => {
    expect(isAgenticIdentityAccountId("p0a-0123456789abcdef0123")).toBe(false);
  });

  it("keeps the account id inside Google's 6-30 character range", () => {
    expect(ACCOUNT_ID).toMatch(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/);
    const longest = "p0a-extraordinary-hippo-1f2e3d4c";
    expect(longest.length).toBeGreaterThan(30);
    expect(isAgenticIdentityAccountId(longest)).toBe(false);
    expect(isAgenticIdentityAccountId("p0a-adventurous-ape-1f2e3d4c")).toBe(
      true
    );
  });

  it("anchors the address at both ends, so a human can never match it", () => {
    const address = agenticIdentityEmail(ACCOUNT_ID, "p0-identities");
    expect(address).toBe(`${ACCOUNT_ID}@p0-identities.iam.gserviceaccount.com`);
    expect(isAgenticIdentityEmail(address, "p0-identities")).toBe(true);
    // Another project's identity project is not this one's namespace.
    expect(isAgenticIdentityEmail(address, "other-project")).toBe(false);
    // A human's Workspace address, which Drive ACLs would happily accept.
    expect(isAgenticIdentityEmail("alice@example.com", "p0-identities")).toBe(
      false
    );
    // A service account that is not an agentic identity.
    expect(
      isAgenticIdentityEmail(
        "p0-security-perimeter-sa@p0-identities.iam.gserviceaccount.com",
        "p0-identities"
      )
    ).toBe(false);
    // Suffix smuggling.
    expect(
      isAgenticIdentityEmail(
        `${ACCOUNT_ID}@p0-identities.iam.gserviceaccount.com.evil.test`,
        "p0-identities"
      )
    ).toBe(false);
    expect(
      isAgenticIdentityEmail(
        `${ACCOUNT_ID}@evil.test@p0-identities.iam.gserviceaccount.com`,
        "p0-identities"
      )
    ).toBe(false);
  });

  it("namespaces the subject under agentic-identity, never mcps", () => {
    expect(isAgenticIdentitySubject("agentic-identity/0123456789abcdef")).toBe(
      true
    );
    expect(isAgenticIdentitySubject("agentic-identity/0123456789abcde")).toBe(
      false
    );
    expect(isAgenticIdentitySubject("mcps/backend/0123456789abcdef")).toBe(
      false
    );
    expect(
      isAgenticIdentitySubject("x/agentic-identity/0123456789abcdef")
    ).toBe(false);
  });

  it("parses a workload identity principal into pool project, pool and subject", () => {
    const member =
      "principal://iam.googleapis.com/projects/123456789/locations/global/" +
      "workloadIdentityPools/p0-pool/subject/agentic-identity/0123456789abcdef";
    expect(parseWorkloadIdentityPrincipal(member)).toEqual({
      poolProjectNumber: "123456789",
      poolId: "p0-pool",
      subject: "agentic-identity/0123456789abcdef",
    });
    expect(parseWorkloadIdentityPrincipal("user:alice@example.com")).toBe(
      undefined
    );
    // Principal identifiers carry the project number, not the id.
    expect(
      parseWorkloadIdentityPrincipal(
        "principal://iam.googleapis.com/projects/my-project/locations/global/" +
          "workloadIdentityPools/p0-pool/subject/agentic-identity/0123456789abcdef"
      )
    ).toBe(undefined);
  });
});
