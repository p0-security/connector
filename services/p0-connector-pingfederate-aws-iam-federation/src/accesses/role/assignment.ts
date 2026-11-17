import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { App } from "../../account.ts";
import { toConnectorError } from "../../errors.ts";
import {
  type Scim,
  ScimStatusError,
  scimClient,
} from "../../pingfederate/scim.ts";
import { readScimPassword } from "../../secrets.ts";

/** One role label for one user, by the user's SCIM ID, on the app. */
export type RoleAssignment = App & { userId: string; role: string };

const rethrowMapped = (error: unknown): never => {
  throw toConnectorError(error);
};

const isNotFound = (error: unknown) =>
  error instanceof ScimStatusError && error.status === 404;

const withScim = async <T>(
  target: App,
  logger: Logger,
  use: (scim: Scim) => Promise<T>
): Promise<T> => {
  const password = await readScimPassword(target.scimPassword, logger);
  return use(scimClient(target, password));
};

/** The SCIM ID of the one user with the work email `email`, or `null` if there is none. */
export const findUserId = (
  target: App,
  email: string,
  logger: Logger
): Promise<string | null> =>
  withScim(target, logger, async (scim) => {
    const ids = await scim.findUsers(email).catch(rethrowMapped);
    if (ids.length > 1) {
      throw new ConnectorError({
        message: `More than one user in PingFederate has the email ${email}. Give the email to one user only.`,
        payload: { count: ids.length },
        type: "validation_error",
      });
    }
    const [id] = ids;
    if (id === null) {
      throw new ConnectorError({
        message:
          "PingFederate found the user but gave no SCIM ID. Check the Read Users mapping of the SCIM IdP connection: its LDAP attribute source must have no ID.",
        payload: {},
        type: "validation_error",
      });
    }
    return id ?? null;
  });

/** Adds the role to the user's role attribute. Does nothing if the user has it. */
export const addRole = (
  { userId, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> =>
  withScim(target, logger, async (scim) => {
    await scim
      .addValue(userId, target.roleAttribute, role)
      .catch((error: unknown) => {
        if (isNotFound(error)) {
          throw new ConnectorError({
            message: `PingFederate has no user with the SCIM ID "${userId}".`,
            payload: {},
            type: "object_not_found",
          });
        }
        return rethrowMapped(error);
      });
    logger.info({ userId }, "added the role to the user");
    return null;
  });

/**
 * Removes the role from the user's role attribute. Does nothing if the user,
 * or their role, is already gone.
 */
export const removeRole = (
  { userId, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> =>
  withScim(target, logger, async (scim) => {
    await scim
      .removeValue(userId, target.roleAttribute, role)
      .catch((error: unknown) => {
        if (isNotFound(error)) {
          logger.warn(
            { userId },
            "PingFederate has no such user; nothing to remove"
          );
          return;
        }
        return rethrowMapped(error);
      });
    logger.info({ userId }, "removed the role from the user");
    return null;
  });
