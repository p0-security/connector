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

import {
  TARGET_ID_PATTERN,
  type Target,
  targetIdOfGrantSecret,
} from "./context.ts";
import {
  type Connect,
  type PgSession,
  connect as connectWithTls,
  withSession,
} from "./postgres/client.ts";

/** The environment variable that holds the manager mapping. */
const MANAGER_SECRET_ARNS = "MANAGER_SECRET_ARNS";

/** Opens the shared secret manager client, of which the connector only
 * reads a secret's value. */
export type ConnectSecretManager = (
  config: SecretManagerProviderConfig
) => Promise<{
  getSecretValue: (params: {
    ref: SecretRef;
  }) => Promise<{ value: SecretPayload }>;
}>;

/** What stands in for the connector's environment, AWS and PostgreSQL in
 * tests. */
export type ManagerDependencies = {
  env?: NodeJS.ProcessEnv;
  connectSecretManager?: ConnectSecretManager;
  connect?: Connect;
};

// Closed, so that the mapping can't send the connector's calls to an
// endpoint outside AWS's regional ones. The region has the shape of `region`
// in ./context.ts.
const MANAGER_SECRET_ARN =
  /^arn:aws(-cn|-us-gov)?:secretsmanager:[a-z]{2}(-[a-z]+)+-\d{1,2}:\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;

const managerSecret = z
  .object({
    arn: z.string().regex(MANAGER_SECRET_ARN),
    targetId: z.string().regex(TARGET_ID_PATTERN),
  })
  .transform(({ arn, targetId }) => {
    const [, , , region = ""] = arn.split(":");
    return { arn, region, targetId };
  });

/** A manager's secret, the region its ARN names, and the id of the target
 * whose grant secrets it may be used for. */
export type ManagerSecret = z.infer<typeof managerSecret>;

/** The manager mapping: target host to the ARN of that target's manager
 * secret, and to the target id that the target's grant secrets name. */
const managerMapping = z.record(z.string().min(1), managerSecret);

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

/**
 * The manager secret of the target at `host`, from the manager mapping. The
 * mapping is read on each call, so that an unusable one fails the call, as
 * install validation reports, and not the Lambda's start.
 */
export const managerSecretFor = (
  host: string,
  env: NodeJS.ProcessEnv = process.env
): ManagerSecret => {
  const text = env[MANAGER_SECRET_ARNS];
  if (!text) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The connector's ${MANAGER_SECRET_ARNS} environment variable is not set. Set it to a JSON object from each target's host to the ARN of its manager secret and its target id.`,
      payload: { host },
    });
  }
  const mapping = managerMapping.safeParse(parseJson(text));
  if (!mapping.success) {
    throw new ConnectorError({
      type: "validation_error",
      message: `The connector's ${MANAGER_SECRET_ARNS} environment variable is not a JSON object from each target's host to the ARN of a Secrets Manager secret and a target id.`,
      payload: { host },
    });
  }
  const entry = Object.entries(mapping.data).find(
    ([mapped]) => mapped.toLowerCase() === host.toLowerCase()
  );
  if (!entry) {
    throw new ConnectorError({
      type: "object_not_found",
      message: `The connector's ${MANAGER_SECRET_ARNS} environment variable has no manager secret for this target's host.`,
      payload: { host },
    });
  }
  return entry[1];
};

/**
 * Whether `secretName`, a name that matches `GRANT_SECRET_NAME_PATTERN`, is a
 * grant secret of the target that `secret` is the manager secret of. Nothing
 * else ties a grant secret's `<target id>` segment to the target the request
 * names, so the grant path checks this before it calls Secrets Manager or the
 * database.
 */
export const isGrantSecretOfManagerTarget = (
  secretName: string,
  secret: ManagerSecret
) => targetIdOfGrantSecret(secretName) === secret.targetId;

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

/** Reads the manager's username and password. Neither is logged, and no
 * error holds either. */
const readManagerCredential = async (
  { arn, region }: ManagerSecret,
  connectSecretManager: ConnectSecretManager
) => {
  const { value } = await connectSecretManager({ provider: "aws", region })
    .then((secrets) => secrets.getSecretValue({ ref: refOf(arn) }))
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
 * Runs `run` signed in to `target` as its manager, then closes the
 * connection. The driver connects on its first statement, so that is where a
 * refused sign-in surfaces.
 */
export const withManager = async <T>(
  target: Target,
  secret: ManagerSecret,
  dependencies: ManagerDependencies,
  logger: Logger,
  run: (session: PgSession) => Promise<T>
): Promise<T> => {
  const {
    connectSecretManager = createSecretManagerClient,
    connect = connectWithTls,
  } = dependencies;
  const credential = await readManagerCredential(secret, connectSecretManager);
  return withSession(connect({ ...target, ...credential }), logger, run);
};
