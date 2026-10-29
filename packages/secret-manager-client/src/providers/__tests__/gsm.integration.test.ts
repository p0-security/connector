import { createClients } from "@p0security/connector-gcloud-common";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  SecretAlreadyExistsError,
  SecretNotFoundError,
  SecretVersionNotFoundError,
} from "../../errors.ts";
import { createSecretManagerClient } from "../../index.ts";
import type {
  SecretManagerClient,
  SecretRef,
  SecretVersionRef,
} from "../../types.ts";

/**
 * Live integration test for the GSM provider. Exercises the full
 * SecretManagerClient interface against a real GCP project, creating and
 * tearing down a throwaway secret.
 *
 * Requires `gcloud auth login --update-adc` to have been run locally (auth
 * is resolved via Application Default Credentials by @p0security/connector-gcloud-common),
 * plus `GCP_PROJECT_ID` set to a project where the caller has been granted
 * the secretManager.Editor role (or equivalent). Skips cleanly if
 * GCP_PROJECT_ID isn't set. Excluded from the default vitest run — see root
 * vitest.config.ts — run explicitly via `yarn test:integration` from this
 * package.
 */
describe.skipIf(!process.env.GCP_PROJECT_ID)("GSM live integration", () => {
  const projectId = process.env.GCP_PROJECT_ID as string;
  const secretName = `p0-secret-manager-client-live-test-${Date.now()}`;

  let client: SecretManagerClient;
  let ref: SecretRef | undefined;
  let firstVersionRef: SecretVersionRef | undefined;

  beforeAll(async () => {
    client = await createSecretManagerClient({ provider: "gcp", projectId });
  });

  afterAll(async () => {
    if (!ref) return;
    // SecretManagerClient has no deleteSecret method (only deleteSecretVersion),
    // so teardown drops to the raw GCP client to remove the whole container.
    const { secretManager } = await createClients();
    await secretManager.projects.secrets.delete({ name: ref });
  });

  it("createSecret creates a secret with no initial version", async () => {
    const metadata = await client.createSecret({ name: secretName });
    ref = metadata.ref;
    expect(metadata.name).toBe(secretName);

    const versions = await client.getSecretVersions({ ref: metadata.ref });
    expect(versions).toHaveLength(0);
  });

  it("createSecret throws SecretAlreadyExistsError on a duplicate name", async () => {
    await expect(client.createSecret({ name: secretName })).rejects.toThrow(
      SecretAlreadyExistsError
    );
  });

  it("getAllSecrets includes the created secret", async () => {
    const secrets = await client.getAllSecrets();
    expect(secrets.some((s) => s.ref === ref)).toBe(true);
  });

  it("createSecretVersion adds the first enabled version", async () => {
    if (!ref) throw new Error("missing secret ref");
    await client.createSecretVersion({ ref, type: "random", bytes: 32 });

    const versions = await client.getSecretVersions({ ref });
    expect(versions).toHaveLength(1);
    expect(versions[0]?.state).toBe("enabled");
    firstVersionRef = versions[0]?.ref;
  });

  it("createSecretVersion adds a second enabled version", async () => {
    if (!ref) throw new Error("missing secret ref");
    await client.createSecretVersion({ ref, type: "random", bytes: 32 });

    const versions = await client.getSecretVersions({ ref });
    expect(versions).toHaveLength(2);
    expect(versions.every((v) => v.state === "enabled")).toBe(true);
  });

  it("getSecretValue reads back the latest version's value", async () => {
    if (!ref) throw new Error("missing secret ref");
    const value = Buffer.from(`live-test-value-${Date.now()}`);
    await client.createSecretVersion({ ref, type: "value", value });

    const { value: readValue, version } = await client.getSecretValue({ ref });
    expect(Buffer.from(readValue)).toEqual(value);
    expect(version.state).toBe("enabled");
  });

  it("disableSecretVersion transitions the first version to disabled", async () => {
    if (!ref || !firstVersionRef) throw new Error("missing refs");
    await client.disableSecretVersion({ ref: firstVersionRef });

    const versions = await client.getSecretVersions({ ref });
    expect(versions.find((v) => v.ref === firstVersionRef)?.state).toBe(
      "disabled"
    );
  });

  it("deleteSecretVersion transitions the first version to destroyed", async () => {
    if (!ref || !firstVersionRef) throw new Error("missing refs");
    await client.deleteSecretVersion({ ref: firstVersionRef });

    const versions = await client.getSecretVersions({ ref });
    expect(versions.find((v) => v.ref === firstVersionRef)?.state).toBe(
      "destroyed"
    );
  });

  it("getSecretVersions throws SecretNotFoundError for an unknown secret", async () => {
    await expect(
      client.getSecretVersions({
        ref: `projects/${projectId}/secrets/does-not-exist-${Date.now()}` as SecretRef,
      })
    ).rejects.toThrow(SecretNotFoundError);
  });

  it("disableSecretVersion throws SecretVersionNotFoundError for an unknown version", async () => {
    await expect(
      client.disableSecretVersion({
        ref: `${ref}/versions/999999` as SecretVersionRef,
      })
    ).rejects.toThrow(SecretVersionNotFoundError);
  });
});
