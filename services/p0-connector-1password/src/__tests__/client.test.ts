import { beforeEach, describe, expect, it, vi } from "vitest";

import { onePasswordClientFor } from "../client.ts";
import { AWS_SECRET, GCP_SECRET } from "./fixtures.ts";

// The SDK's client, which signs in with whatever token it's given. Each
// sign-in answers with a client of its own, named for its token.
const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("@1password/sdk", () => sdk);

// Each test starts its cache keys afresh: the cache lives for the module.
let run = 0;
const pointer = <T extends { secretId: string }>(secret: T): T => ({
  ...secret,
  secretId: `${secret.secretId}-${run}`,
});

const secret = (token: string, version = "v1") => ({ token, version });

beforeEach(() => {
  run += 1;
  vi.clearAllMocks();
  sdk.createClient.mockImplementation(async ({ auth }: { auth: string }) => ({
    signedInWith: auth,
  }));
});

describe("onePasswordClientFor", () => {
  it("signs in with the token, as P0", async () => {
    await expect(
      onePasswordClientFor(pointer(AWS_SECRET), secret("ops_a"))
    ).resolves.toEqual({ signedInWith: "ops_a" });
    expect(sdk.createClient).toHaveBeenCalledWith({
      auth: "ops_a",
      integrationName: "P0 Security",
      integrationVersion: "1.0.0",
    });
  });

  it("signs in once per pointer and secret version", async () => {
    const tokenSecret = pointer(AWS_SECRET);

    const first = await onePasswordClientFor(tokenSecret, secret("ops_a"));
    const second = await onePasswordClientFor(tokenSecret, secret("ops_a"));

    expect(second).toBe(first);
    expect(sdk.createClient).toHaveBeenCalledTimes(1);
  });

  it("signs in again once the secret is rotated", async () => {
    const tokenSecret = pointer(AWS_SECRET);
    await onePasswordClientFor(tokenSecret, secret("ops_a", "v1"));

    await expect(
      onePasswordClientFor(tokenSecret, secret("ops_b", "v2"))
    ).resolves.toEqual({ signedInWith: "ops_b" });
  });

  // Otherwise one account's calls would go out as another account's service
  // account.
  it.each([
    ["another secret", { ...AWS_SECRET, secretId: "other" }],
    ["another region", { ...AWS_SECRET, region: "eu-west-1" }],
    ["another cloud", GCP_SECRET],
  ])(
    "keeps a client apart for a pointer to %s, at the same version",
    async (_case, other) => {
      await onePasswordClientFor(pointer(AWS_SECRET), secret("ops_a"));

      await expect(
        onePasswordClientFor(pointer(other), secret("ops_b"))
      ).resolves.toEqual({ signedInWith: "ops_b" });
    }
  );

  it("keeps a Google pointer apart from one to another project", async () => {
    await onePasswordClientFor(pointer(GCP_SECRET), secret("ops_a"));

    await expect(
      onePasswordClientFor(
        pointer({ ...GCP_SECRET, projectId: "acme-dev" }),
        secret("ops_b")
      )
    ).resolves.toEqual({ signedInWith: "ops_b" });
  });

  it("signs in again after a sign-in fails", async () => {
    const tokenSecret = pointer(AWS_SECRET);
    sdk.createClient.mockRejectedValueOnce(new Error("refused"));

    await expect(
      onePasswordClientFor(tokenSecret, secret("ops_a"))
    ).rejects.toThrow("refused");
    await expect(
      onePasswordClientFor(tokenSecret, secret("ops_a"))
    ).resolves.toEqual({ signedInWith: "ops_a" });
  });

  it("keeps a newer client when an older sign-in fails after it", async () => {
    const tokenSecret = pointer(AWS_SECRET);
    let refuse: (error: Error) => void = () => {};
    sdk.createClient.mockImplementationOnce(
      () => new Promise((_resolve, reject) => (refuse = reject))
    );
    const older = onePasswordClientFor(tokenSecret, secret("ops_a", "v1"));
    // Start the newer once the older one is signing in. Two sign-ins racing
    // on the SDK's dynamic import sometimes get Vitest's real module in
    // place of the mock.
    await vi.waitFor(() => expect(sdk.createClient).toHaveBeenCalledTimes(1));
    const newer = await onePasswordClientFor(
      tokenSecret,
      secret("ops_b", "v2")
    );

    refuse(new Error("refused"));
    await expect(older).rejects.toThrow("refused");

    await expect(
      onePasswordClientFor(tokenSecret, secret("ops_b", "v2"))
    ).resolves.toBe(newer);
    expect(sdk.createClient).toHaveBeenCalledTimes(2);
  });
});
