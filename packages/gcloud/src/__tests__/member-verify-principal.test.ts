import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const getOrgId = vi.fn();
const getOrgIdByProjectNumber = vi.fn();

vi.mock("../helpers/ancestry.ts", () => ({
  getOrgId: (...args: unknown[]) => getOrgId(...args),
  getOrgIdByProjectNumber: (...args: unknown[]) =>
    getOrgIdByProjectNumber(...args),
}));

const METADATA = {
  serviceAccountEmail:
    "p0-security-perimeter-sa@customer.iam.gserviceaccount.com",
  projectId: "customer",
};

const principal = (
  subject: string,
  projectNumber = "123456789",
  pool = "p0-pool"
) =>
  `principal://iam.googleapis.com/projects/${projectNumber}/locations/global/` +
  `workloadIdentityPools/${pool}/subject/${subject}`;

const verifier = async () => {
  const { newMemberVerifier } = await import("../member-verify.ts");
  return newMemberVerifier(undefined as any, METADATA);
};

describe("member-verify: workload identity principals", () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...OLD_ENV };
    getOrgId.mockResolvedValue("111111111111");
    getOrgIdByProjectNumber.mockResolvedValue("111111111111");
  });

  afterEach(() => {
    process.env = OLD_ENV;
    vi.clearAllMocks();
  });

  it("accepts an agentic identity subject in a pool in the same organization", async () => {
    process.env.DOMAIN_ALLOW_PATTERN = ".*@(example[.]com)$";
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember(
        principal("agentic-identity/0123456789abcdef")
      )
    ).resolves.toBeUndefined();
  });

  it("rejects a subject outside the agentic-identity namespace", async () => {
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember(principal("mcps/backend/0123456789abcdef"))
    ).rejects.toThrow(/does not name an agentic identity subject/);
  });

  it("rejects a pool in another organization", async () => {
    getOrgIdByProjectNumber.mockResolvedValue("999999999999");
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember(
        principal("agentic-identity/0123456789abcdef")
      )
    ).rejects.toThrow(/outside this organization/);
  });

  it("rejects a pool whose project has no organization", async () => {
    getOrgIdByProjectNumber.mockResolvedValue(undefined);
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember(
        principal("agentic-identity/0123456789abcdef")
      )
    ).rejects.toThrow(/outside this organization/);
  });

  it("rejects a malformed principal rather than falling through to the domain check", async () => {
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember("principal://something-else")
    ).rejects.toThrow(/not a recognized workload identity principal/);
  });

  // An unset DOMAIN_ALLOW_PATTERN compiles to the empty regex, which matches
  // everything. The principal branch must validate positively rather than
  // inherit that.
  it("does not fail open when DOMAIN_ALLOW_PATTERN is unset", async () => {
    delete process.env.DOMAIN_ALLOW_PATTERN;
    getOrgIdByProjectNumber.mockResolvedValue("999999999999");
    const memberVerifier = await verifier();
    await expect(
      memberVerifier.verifyMember(
        principal("agentic-identity/0123456789abcdef")
      )
    ).rejects.toThrow(/outside this organization/);
    await expect(
      memberVerifier.verifyMember(principal("anything-at-all"))
    ).rejects.toThrow(/does not name an agentic identity subject/);
  });
});
