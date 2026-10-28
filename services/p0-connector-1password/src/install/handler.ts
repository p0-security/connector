import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type ConnectorErrorOptions,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import {
  type AccountCredentials,
  accountCredentials,
} from "../accesses/share/definition.ts";
import { requireAllowedDomains } from "../allowed-domains.ts";
import { type OnePasswordClient, onePasswordClientFor } from "../client.ts";
import { sdkFailureOf, toConnectorError } from "../onepassword/errors.ts";
import { failureFacts } from "../onepassword/failure.ts";
import { allowsSharingByEmail } from "../onepassword/policy.ts";
import { listVaults, newVaultReader } from "../onepassword/vault.ts";
import { getServiceAccountToken } from "../secrets.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, in the order they run, by the name a failure reports in `payload.step`. */
type Step = "authenticate" | "domains" | "secret" | "sharing" | "vaults";

/** What the checks on 1Password share. */
export type Check = {
  client: OnePasswordClient;
  logger: Logger;
};

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
  new ConnectorError({ type, message, payload: { ...payload, step } });

/**
 * The failure of an SDK call at `step`. A rate limit and an expired token say
 * so. Anything else is worded as `otherwise` says: the SDK's errors carry no
 * more than a message, which the connector never repeats.
 */
const failedAt = (
  step: Step,
  error: unknown,
  otherwise: Pick<ConnectorErrorOptions, "message" | "type">
) => {
  const mapped =
    error instanceof ConnectorError || sdkFailureOf(error) !== undefined
      ? toConnectorError(error).data
      : { ...otherwise, payload: failureFacts(error) };
  return failedCheck({ ...mapped, step });
};

/** `vaults`: the service account can see at least one vault. Returns their
 * IDs, in the order 1Password lists them. */
const checkVaults = async ({ client }: Check): Promise<string[]> => {
  const vaults = await listVaults(client).catch((error: unknown) => {
    throw failedAt("vaults", error, {
      type: "insufficient_privileges",
      message:
        "P0 couldn't list the vaults the service account can see. Check that the service account is active.",
    });
  });
  if (vaults.length === 0) {
    throw failedCheck({
      step: "vaults",
      type: "validation_error",
      message:
        "The service account can't see any vault. In 1Password, give it Read Items and Share Items on each vault people may request items from.",
    });
  }
  return vaults.map(({ id }) => id);
};

/**
 * `sharing`: the account's sharing policy lets the service account share an
 * item with one person, by email. 1Password reads the policy through an item,
 * so this reads it through the first active item of the first vault that has
 * one, and is skipped with a warning when none has. Returns whether it read
 * the policy.
 *
 * It can't prove a share would be made: 1Password has no call to delete one,
 * so the check makes none.
 */
const checkSharing = async (
  { client, logger }: Check,
  vaults: readonly string[]
) => {
  const couldNotRead = (error: unknown) =>
    failedAt("sharing", error, {
      type: "insufficient_privileges",
      message:
        "P0 couldn't read 1Password's item sharing policy. Check that the service account has Read Items and Share Items on its vaults.",
    });
  for (const vault of vaults) {
    const reader = newVaultReader(client, vault);
    const [item] = await reader.listItems().catch((error: unknown) => {
      throw couldNotRead(error);
    });
    if (item === undefined) continue;
    const policy = await reader
      .sharingPolicy(item.id)
      .catch((error: unknown) => {
        throw couldNotRead(error);
      });
    if (!allowsSharingByEmail(policy)) {
      throw failedCheck({
        step: "sharing",
        type: "validation_error",
        message:
          "1Password's item sharing policy doesn't allow sharing an item with a specific person by email. Ask a 1Password owner or administrator to allow it.",
      });
    }
    return true;
  }
  logger.warn(
    { vaults: vaults.length },
    "no vault the service account sees has an active item to read the sharing policy through; skipped the sharing check"
  );
  return false;
};

/**
 * The checks on 1Password itself, in order, each failing at its step:
 *
 * 1. `vaults`: the service account can see at least one vault.
 * 2. `sharing`: the account's sharing policy allows sharing with a person, by
 *    email.
 */
export const checkOnePassword = async (
  check: Check
): Promise<Pick<InstallValidation, "sharingChecked" | "vaultCount">> => {
  const vaults = await checkVaults(check);
  const sharingChecked = await checkSharing(check, vaults);
  return { vaultCount: vaults.length, sharingChecked };
};

/**
 * `domains`: the connector's `DOMAIN_ALLOW_PATTERN` as deployed. Both entry
 * points refuse to start without a usable one, so this fails only for a
 * connector run some other way.
 */
const checkDomains = (): string => {
  try {
    return requireAllowedDomains().pattern;
  } catch (error) {
    throw failedCheck({
      step: "domains",
      type: "validation_error",
      message: error instanceof Error ? error.message : String(error),
    });
  }
};

/**
 * Install validation for one 1Password account, as ordered steps that each
 * throw with their `payload.step`:
 *
 * 1. `secret`: the connector can read the service account's token.
 * 2. `authenticate`: 1Password accepts it.
 * 3. `vaults` and `sharing`: {@link checkOnePassword}.
 * 4. `domains`: the connector has an allowed-domain pattern.
 */
const getInstallValidation = async (
  { tokenSecret }: AccountCredentials,
  logger: Logger
): Promise<InstallValidation> => {
  const secret = await getServiceAccountToken(tokenSecret).catch(
    (error: unknown) => {
      // The accesses read the secret too, so the read doesn't name a step.
      throw error instanceof ConnectorError
        ? failedCheck({ ...error.data, step: "secret" })
        : error;
    }
  );
  const client = await onePasswordClientFor(tokenSecret, secret).catch(
    (error: unknown) => {
      throw failedAt("authenticate", error, {
        type: "insufficient_privileges",
        message: `1Password didn't accept the token in ${tokenSecret.secretId}. Check that it holds the account's service account token, which starts with ops_, and that the service account is active.`,
      });
    }
  );
  const checked = await checkOnePassword({ client, logger });
  return { ...checked, allowedDomains: checkDomains() };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  // Logs each validation and its failure, as the access routes do.
  const procedure = withRouteLogging(t.procedure);

  return router({
    get: procedure
      .input(accountCredentials.parse)
      .query(async ({ input, ctx }) => {
        const validation = await getInstallValidation(input, ctx.logger);
        ctx.logger.info(validation, "validated the 1Password account");
        return validation;
      }),
  });
};
