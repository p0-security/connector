import type * as SecretManagerClientModule from "@p0security/connector-secret-manager-client";
import type { SecretRef } from "@p0security/connector-secret-manager-client";

/**
 * An in-memory Google Secret Manager, keyed by `<projectId>/<secret name>`.
 * A secret without a value exists but has no version.
 */
export const fakeSecretManager = (actual: typeof SecretManagerClientModule) => {
  const secrets = new Map<string, string | undefined>();
  const keyOf = (projectId: string, ref: string) =>
    `${projectId}/${ref.split("/").pop() ?? ref}`;
  const failures = new Map<string, Error>();
  // How long a value read takes to answer, in milliseconds. None by default.
  const readDelay = { ms: 0 };

  const createSecretManagerClient = async (config: { projectId: string }) => {
    const { projectId } = config;
    const fail = (op: string) => {
      const error = failures.get(op);
      if (error !== undefined) throw error;
    };
    const notFound = (ref: string) =>
      new actual.SecretNotFoundError(ref as SecretRef);
    return {
      getSecretValue: async ({ ref }: { ref: string }) => {
        if (readDelay.ms > 0)
          await new Promise((resolve) => setTimeout(resolve, readDelay.ms));
        fail("getSecretValue");
        const value = secrets.get(keyOf(projectId, ref));
        if (value === undefined) throw notFound(ref);
        return { value: Buffer.from(value) };
      },
      getSecret: async ({ ref }: { ref: string }) => {
        fail("getSecret");
        if (!secrets.has(keyOf(projectId, ref))) throw notFound(ref);
        const name = ref.split("/").pop() ?? ref;
        return { ref: `projects/${projectId}/secrets/${name}`, name };
      },
      createSecret: async ({ name }: { name: string }) => {
        fail("createSecret");
        const key = keyOf(projectId, name);
        if (secrets.has(key)) throw new actual.SecretAlreadyExistsError(name);
        secrets.set(key, undefined);
        return { ref: `projects/${projectId}/secrets/${name}`, name };
      },
      createSecretVersion: async ({
        ref,
        value,
      }: {
        ref: string;
        value: Buffer;
      }) => {
        fail("createSecretVersion");
        const key = keyOf(projectId, ref);
        if (!secrets.has(key)) throw notFound(ref);
        secrets.set(key, value.toString("utf8"));
      },
      deleteSecret: async ({ ref }: { ref: string }) => {
        fail("deleteSecret");
        const key = keyOf(projectId, ref);
        if (!secrets.has(key)) throw notFound(ref);
        secrets.delete(key);
      },
    };
  };
  return { secrets, failures, readDelay, createSecretManagerClient };
};

export type FakeSecretManager = ReturnType<typeof fakeSecretManager>;
