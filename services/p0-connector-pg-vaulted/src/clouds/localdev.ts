import {
  SecretAlreadyExistsError,
  type SecretManagerClient,
  SecretNotFoundError,
  type SecretRef,
  type SecretVersionRef,
  type VersionMetadata,
} from "@p0security/connector-secret-manager-client";

import type { CloudConfig } from "./index.ts";

/** A local database has no Secrets Manager, so grant secrets stay in memory. */
const localSecrets = new Map<string, Buffer | undefined>();

const findSecret = (ref: SecretRef) => {
  if (!localSecrets.has(ref)) throw new SecretNotFoundError(ref);
  return localSecrets.get(ref);
};

const versionOf = (ref: SecretRef): VersionMetadata => ({
  ref: `${ref}:current` as SecretVersionRef,
  secretRef: ref,
  state: "enabled",
  createTime: new Date(),
});

const unsupported = async (): Promise<never> => {
  throw new Error("not supported by the local secret store");
};

export const localSecretManager: SecretManagerClient = {
  createSecret: async ({ name }) => {
    if (localSecrets.has(name)) throw new SecretAlreadyExistsError(name);
    localSecrets.set(name, undefined);
    return { ref: name as SecretRef, name, createTime: new Date() };
  },
  getSecret: async ({ ref }) => {
    findSecret(ref);
    return { ref, name: ref, createTime: new Date() };
  },
  deleteSecret: async ({ ref }) => {
    findSecret(ref);
    localSecrets.delete(ref);
  },
  createSecretVersion: async (params) => {
    findSecret(params.ref);
    if (params.type !== "value") return await unsupported();
    localSecrets.set(params.ref, params.value);
    return versionOf(params.ref);
  },
  getSecretValue: async ({ ref }) => {
    const value = findSecret(ref);
    if (value === undefined) throw new SecretNotFoundError(ref);
    return { value, version: versionOf(ref) };
  },
  getAllSecrets: unsupported,
  getSecretVersions: unsupported,
  disableSecretVersion: unsupported,
  deleteSecretVersion: unsupported,
};

export const localConfig: CloudConfig = {
  fetchDbPassword: async () => "psqlpass",
  poolConfig: async () => ({}),
  sslConfig: async () => false,
  secretManager: async () => localSecretManager,
};
