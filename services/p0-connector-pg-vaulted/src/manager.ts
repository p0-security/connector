import { ConnectorError, type Logger } from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  SecretNotFoundError,
  type SecretPayload,
  type SecretRef,
  UnauthorizedError,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";
import { z } from "zod";

import type { Target } from "./context.ts";
import {
  type Connect,
  type PgSession,
  connect as connectWithTls,
  withSession,
} from "./postgres/client.ts";

/** Opens the shared secret manager client, of which the connector only
 * reads a secret's value. */
export type ConnectSecretManager = (
  config: SecretManagerProviderConfig
) => Promise<{
  getSecretValue: (params: {
    ref: SecretRef;
  }) => Promise<{ value: SecretPayload }>;
}>;

/** What stands in for AWS and PostgreSQL in tests. */
export type ManagerDependencies = {
  connectSecretManager?: ConnectSecretManager;
  connect?: Connect;
};

/** The secret's value, in the shape AWS writes for a database credential.
 * Its other keys are ignored. */
const managerCredential = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

/** `undefined` for text that is not JSON. The parser's own error quotes the
 * text, which may be a secret's value. */
const parseJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

// The shared client's refs are a brand on a string, which only a cast makes.
const refOf = (arn: string) => arn as SecretRef;

/**
 * A Secrets Manager failure, without its cause. The call that failed is the
 * one whose response holds the manager's password, and the connector does
 * not vouch for what an SDK error carries, so the cause is never passed on
 * or logged.
 */
const secretManagerError = (error: unknown) => {
  if (error instanceof SecretNotFoundError) {
    return new ConnectorError({
      type: "object_not_found",
      message: "The manager secret does not exist or has no value.",
      payload: {},
    });
  }
  if (error instanceof UnauthorizedError) {
    return new ConnectorError({
      type: "insufficient_privileges",
      message:
        "Secrets Manager refused to let the connector read the manager secret. Give the connector's role secretsmanager:GetSecretValue on it.",
      payload: {},
    });
  }
  return new ConnectorError({
    type: "upstream_unavailable",
    message: "The connector could not read the manager secret.",
    payload: {},
  });
};

/** The manager's username and password. */
export type ManagerCredential = z.infer<typeof managerCredential>;

/**
 * Reads the manager's username and password from the secret that
 * `target.managerSecretArn` names, in the region its ARN names. The request
 * names the secret, and the connector's IAM limits which secrets it can
 * read. Neither value is logged, and no error holds either.
 */
export const readManagerCredential = async (
  { managerSecretArn }: Target,
  dependencies: ManagerDependencies
): Promise<ManagerCredential> => {
  const { connectSecretManager = createSecretManagerClient } = dependencies;
  const [, , , region = ""] = managerSecretArn.split(":");
  const { value } = await connectSecretManager({ provider: "aws", region })
    .then((secrets) => secrets.getSecretValue({ ref: refOf(managerSecretArn) }))
    .catch((error: unknown) => {
      throw secretManagerError(error);
    });
  const credential = managerCredential.safeParse(
    parseJson(typeof value === "string" ? value : value.toString("utf8"))
  );
  if (!credential.success) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The manager secret's value must be a JSON object with a username and a password.",
      payload: {},
    });
  }
  return credential.data;
};

/**
 * Runs `run` signed in to `target` as its manager, with the credential
 * {@link readManagerCredential} read, then closes the connection. The driver
 * connects on its first statement, so that is where a refused sign-in
 * surfaces.
 */
export const withManager = async <T>(
  target: Target,
  credential: ManagerCredential,
  dependencies: ManagerDependencies,
  logger: Logger,
  run: (session: PgSession) => Promise<T>
): Promise<T> => {
  const { connect = connectWithTls } = dependencies;
  const { host, port, database } = target;
  return withSession(
    connect({ host, port, database, ...credential }),
    logger,
    run
  );
};
