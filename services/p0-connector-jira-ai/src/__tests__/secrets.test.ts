import type * as SecretManagerClientModule from "@p0security/secret-manager-client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { readSecretString } from "../secrets.ts";
import { SITE, logger } from "./fixtures.ts";
import type { FakeSecretManager } from "./secret-manager-mock.ts";

const vault = vi.hoisted((): { fake?: FakeSecretManager } => ({}));

vi.mock("@p0security/secret-manager-client", async (importOriginal) => {
  const actual = await importOriginal<typeof SecretManagerClientModule>();
  const { fakeSecretManager } = await import("./secret-manager-mock.ts");
  const fake = fakeSecretManager(actual);
  vault.fake = fake;
  return {
    ...actual,
    createSecretManagerClient: fake.createSecretManagerClient,
  };
});

const fakeVault = () => {
  if (vault.fake === undefined)
    throw new Error("the secret manager isn't mocked");
  return vault.fake;
};

const WHAT = "the Jira admin client secret";

const read = () => readSecretString(SITE.adminSecret, WHAT, logger);

beforeEach(() => {
  const { secrets, failures } = fakeVault();
  secrets.clear();
  failures.clear();
});

describe("readSecretString", () => {
  it("returns the value without surrounding whitespace", async () => {
    fakeVault().secrets.set("acme-vault/jira-admin", " admin-secret\n");

    await expect(read()).resolves.toBe("admin-secret");
  });

  it("fails with validation_error for a whitespace-only value", async () => {
    fakeVault().secrets.set("acme-vault/jira-admin", " \n");

    await expect(read()).rejects.toMatchObject({
      data: { type: "validation_error" },
    });
  });

  it("fails with validation_error for an empty value", async () => {
    // What the client throws when Google returns a version with no payload.
    fakeVault().failures.set(
      "getSecretValue",
      new Error(
        'GCP Secret Manager returned a version with no payload data for "jira-admin"'
      )
    );

    await expect(read()).rejects.toMatchObject({
      data: {
        type: "validation_error",
        message: `The Jira admin client secret in Google Secret Manager is empty. Add a new version of the secret whose whole value is the Jira admin client secret.`,
      },
    });
  });

  it("fails with unknown for another error, without quoting it", async () => {
    fakeVault().failures.set(
      "getSecretValue",
      new Error("projects/acme-vault/secrets/jira-admin: internal")
    );

    const error: unknown = await read().catch((error: unknown) => error);
    expect(error).toMatchObject({ data: { type: "unknown" } });
    expect(JSON.stringify(error)).not.toContain("jira-admin");
  });
});
