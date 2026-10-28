import { afterAll, beforeAll, describe, expect, it } from "vitest";

describe("member-verify", () => {
  const OLD_ENV = process.env;
  beforeAll(() => {
    // Allowed domains are example.com and example.org
    process.env.DOMAIN_ALLOW_PATTERN = ".*@(example[.]com|example[.]org)$";
  });
  afterAll(() => {
    process.env = OLD_ENV;
  });
  it("should verify allowed domain for user", async () => {
    const { newMemberVerifier } = await import("../member-verify.js");
    const memberVerifier = newMemberVerifier(undefined as any, {
      serviceAccountEmail: "test@test-project.serviceaccount.com",
      projectId: "test-project",
    });
    await expect(
      memberVerifier.verifyMember("user:test@example.com")
    ).resolves.not.toThrow();
    await expect(
      memberVerifier.verifyMember("user:test@example.org")
    ).resolves.not.toThrow();
    await expect(
      memberVerifier.verifyMember("user:test@example1.com")
    ).rejects.toMatchSnapshot();
    await expect(
      memberVerifier.verifyMember(
        "serviceAccount:test@test-project.serviceaccount.com"
      )
    ).rejects.toMatchSnapshot();
  });
});
