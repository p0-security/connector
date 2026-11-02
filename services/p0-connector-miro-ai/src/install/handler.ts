import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import {
  type MiroClient,
  type Pause,
  type TokenInfo,
  newMiroApi,
  newMiroClient,
} from "../miro/client.ts";
import { toConnectorError } from "../miro/errors.ts";
import { readToken } from "../secrets.ts";
import { type InstallInput, installInput } from "../team.ts";
import { type InstallValidation, REQUIRED_SCOPES } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "boards" | "secret";

/**
 * The error for a failed check. The answer carries facts, not results, so a
 * failure is thrown, and `payload.step` is how P0 tells one from another.
 */
const failedCheck = ({
  step,
  type,
  message,
  payload,
}: Pick<ConnectorErrorOptions, "message" | "type"> &
  Partial<Pick<ConnectorErrorOptions, "payload">> & { step: Step }) =>
  new ConnectorError({ message, payload: { ...payload, step }, type });

/** The failure of a Miro call at `step`, as P0 shows it. */
const failedAt = (step: Step) => (error: unknown) => {
  const mapped = toConnectorError(error);
  throw mapped instanceof ConnectorError
    ? failedCheck({ ...mapped.data, step })
    : mapped;
};

/**
 * `authenticate`: Miro accepts the token (`GET /v1/oauth-token`), says which
 * team it was installed into, and lists every scope in
 * {@link REQUIRED_SCOPES}. A token keeps the scopes it was issued with, so a
 * missing one takes a reinstall, not a change to the app alone (spec V1).
 */
const authenticate = async (client: MiroClient): Promise<TokenInfo> => {
  const info = await client.fetchTokenInfo().catch(failedAt("authenticate"));
  const granted = new Set(info.scopes);
  const missing = REQUIRED_SCOPES.filter((scope) => !granted.has(scope));
  if (missing.length > 0) {
    const scopes = missing.join(", ");
    throw failedCheck({
      message: `The connector user's Miro access token is missing ${missing.length === 1 ? "the scope" : "the scopes"} ${scopes}. Add ${missing.length === 1 ? "the scope" : "them"} to the app, then reinstall it and store the new token.`,
      payload: { missingScopes: scopes },
      step: "authenticate",
      type: "insufficient_privileges",
    });
  }
  return info;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the access token from the secret.
 * 2. `authenticate`: Miro accepts the token, says which team it belongs to,
 *    and the token has every scope the connector needs.
 * 3. `boards`: how many of the team's boards the connector user owns or
 *    co-owns. Zero passes: P0 shows it as a warning.
 *
 * Every check only reads. Nothing of the token is reported.
 */
export const getInstallValidation = async (
  { secret }: InstallInput,
  logger: Logger,
  pause?: Pause
): Promise<InstallValidation> => {
  const client = await readToken(secret, logger)
    .then((token) =>
      newMiroClient(
        newMiroApi({ logger, token, ...(pause === undefined ? {} : { pause }) })
      )
    )
    .catch((error: unknown) => {
      throw error instanceof ConnectorError
        ? failedCheck({ ...error.data, step: "secret" })
        : error;
    });
  const { teamId } = await authenticate(client);
  const shareableBoards = await client
    .countShareableBoards(teamId)
    .catch(failedAt("boards"));
  if (shareableBoards === 0) {
    logger.warn(
      { teamId },
      "the connector user owns or co-owns no board in the team, so none can be requested"
    );
  }
  return { shareableBoards, teamId };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure.input(installInput.parse).query(async ({ input, ctx }) => {
      const validation = await getInstallValidation(input, ctx.logger);
      ctx.logger.info(validation, "validated the Miro team");
      return validation;
    }),
  });
};
