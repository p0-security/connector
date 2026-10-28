import { createClients } from "@p0security/gcloud-common";
import { createSecretManagerClient } from "@p0security/secret-manager-client";
import type { SecretRef } from "@p0security/secret-manager-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { router as secretsRouter } from "../accesses/secrets/handler.ts";
import { t } from "../router.ts";

/**
 * Live integration test for the gsm connector's `secrets` handlers. Exercises
 * every handler through the actual TRPC router (via `createCaller`, in-process,
 * no HTTP server -- see p0-connector-mysql/pg's `__tests__/setup.ts` for the
 * same convention), against a real GCP project.
 *
 * The connector has no create-secret handler (by design -- it only manages
 * versions of secrets that already exist), so setup/teardown of the throwaway
 * secret container drop to `secret-manager-client`/raw GCP calls directly,
 * mirroring `packages/secret-manager-client`'s own `gsm.integration.test.ts`.
 *
 * Requires `gcloud auth login --update-adc` (auth resolves via Application
 * Default Credentials) plus `GCP_PROJECT_ID` set to a project where the caller
 * has been granted the secretManager.Editor role (or equivalent). Skips
 * cleanly if GCP_PROJECT_ID isn't set. Excluded from the default vitest run
 * -- see root vitest.config.ts -- run explicitly via
 * `yarn workspace @p0security/p0-connector-gsm test:integration`.
 */
describe.skipIf(!process.env.GCP_PROJECT_ID)("gsm secrets handlers", () => {
  const project = process.env.GCP_PROJECT_ID as string;
  const name = `p0-connector-gsm-live-test-${Date.now()}`;
  const secretId = { project, name };

  let ref: SecretRef | undefined;

  beforeAll(async () => {
    const client = await createSecretManagerClient({
      provider: "gcp",
      projectId: project,
    });
    const metadata = await client.createSecret({ name });
    ref = metadata.ref;
  });

  afterAll(async () => {
    if (!ref) return;
    // Neither secret-manager-client nor the connector exposes a whole-secret
    // delete, so teardown drops to the raw GCP client to remove the container.
    const { secretManager } = await createClients();
    await secretManager.projects.secrets.delete({ name: ref });
  });

  const caller = secretsRouter(t).createCaller({});

  it("getInstallValidation resolves the runtime service account", async () => {
    const result = await caller.getInstallValidation({});
    expect(result.canAuthenticate).toBe(true);
    expect(result.serviceAccountEmail).toEqual(expect.any(String));
  });

  it("listSecrets finds the created secret by name filter", async () => {
    const result = await caller.listSecrets({
      query: { project, filter: name },
    });
    expect(
      result.secrets.some((secret: { name: string }) => secret.name === name)
    ).toBe(true);
  });

  it("createNewVersion adds the first enabled version", async () => {
    const version = await caller.createNewVersion({ secretId });
    expect(version.version).toBe("1");
    expect(version.state).toBe("ENABLED");
  });

  it("getSecretMetadata reflects the first version", async () => {
    const metadata = await caller.getSecretMetadata({ secretId });
    expect(metadata.versions).toHaveLength(1);
    expect(metadata.versions[0]).toMatchObject({
      version: "1",
      state: "ENABLED",
    });
  });

  it("createNewVersion adds a second enabled version", async () => {
    const version = await caller.createNewVersion({ secretId });
    expect(version.version).toBe("2");
    expect(version.state).toBe("ENABLED");
  });

  it("disableVersion transitions the first version to disabled", async () => {
    await caller.disableVersion({ versionId: { ...secretId, version: "1" } });

    const metadata = await caller.getSecretMetadata({ secretId });
    expect(
      metadata.versions.find((v: { version: string }) => v.version === "1")
        ?.state
    ).toBe("DISABLED");
  });

  it("deleteVersion transitions the first version to destroyed", async () => {
    await caller.deleteVersion({ versionId: { ...secretId, version: "1" } });

    const metadata = await caller.getSecretMetadata({ secretId });
    expect(
      metadata.versions.find((v: { version: string }) => v.version === "1")
        ?.state
    ).toBe("DESTROYED");
  });
});
