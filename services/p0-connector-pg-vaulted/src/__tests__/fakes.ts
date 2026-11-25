import { ConnectorError } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretPayload,
} from "@p0security/connector-secret-manager-client";

import type { ConnectSecretManager } from "../manager.ts";
import { target } from "./fixtures.ts";

/** The fixture target's manager secret, a secret P0 names. */
export const MANAGER_SECRET = target.managerSecret;

/** The connector's environment in Lambda, which reads a manager secret P0
 * names in its `AWS_REGION`. */
export const CONNECTOR_ENV = { AWS_REGION: "us-east-1" };

export const MANAGER = {
  username: "p0_manager",
  password: "correct-horse-battery-staple",
};

// copy of `errorOf`, `connectorErrorOf` and `dataOf` in services/p0-connector-aws-ssm-ai/src/__tests__/fakes.ts
/** The error a call rejected with. */
export const errorOf = async (promise: Promise<unknown>) => {
  const error = await promise.catch((e: unknown) => e);
  if (!(error instanceof Error)) {
    throw new Error(`expected an Error, got ${String(error)}`);
  }
  return error;
};

/** The connector error a call threw, which tRPC can wrap. */
export const connectorErrorOf = (error: Error) => {
  if (error instanceof ConnectorError) return error;
  if (error.cause instanceof ConnectorError) return error.cause;
  throw new Error(`expected a ConnectorError, got ${String(error)}`);
};

/** The data of the connector error a call rejected with. */
export const dataOf = async (promise: Promise<unknown>) =>
  connectorErrorOf(await errorOf(promise)).data;

/**
 * Secrets Manager in memory, by name or ARN. It holds the fixture manager's
 * secret unless given other values, and keeps every read's region and
 * secret.
 */
export const fakeSecretStore = (
  values: Record<string, SecretPayload> = {
    [MANAGER_SECRET]: JSON.stringify(MANAGER),
  }
) => {
  const reads: { config: SecretManagerProviderConfig; ref: string }[] = [];
  /** Every read throws `fail`. */
  const state: { fail?: Error } = {};
  const connectSecretManager: ConnectSecretManager = async (config) => ({
    getSecretValue: async ({ ref }) => {
      reads.push({ config, ref });
      if (state.fail) throw state.fail;
      const value = values[ref];
      if (value === undefined) throw new SecretNotFoundError(ref);
      return { value };
    },
  });
  return { connectSecretManager, reads, state };
};
