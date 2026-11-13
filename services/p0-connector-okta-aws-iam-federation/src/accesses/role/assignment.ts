import { ConnectorError, type Logger } from "@p0security/connector-core";

import type { App } from "../../account.ts";
import {
  type OktaClient,
  type OktaUser,
  connectOkta,
} from "../../okta/client.ts";
import { toConnectorError } from "../../okta/errors.ts";

/** One role label for one user, by the user's primary email, on the app. */
export type RoleAssignment = App & { email: string; role: string };

/** The one Okta user with `email`, or `null` if there is none. */
const findUser = async (
  okta: OktaClient,
  email: string
): Promise<OktaUser | null> => {
  const users = await okta.findUsersByEmail(email);
  if (users.length > 1) {
    throw new ConnectorError({
      message: `More than one Okta user has the email ${email}. Give the email to one user only.`,
      payload: { count: users.length },
      type: "validation_error",
    });
  }
  return users[0] ?? null;
};

const rethrowMapped = (error: unknown): never => {
  throw toConnectorError(error);
};

/** Okta's ID for the user with `email`, or `null` if there is none. */
export const findUserId = async (
  target: App,
  email: string,
  logger: Logger
): Promise<string | null> => {
  const okta = await connectOkta(target, logger).catch(rethrowMapped);
  const user = await findUser(okta, email).catch(rethrowMapped);
  return user?.id ?? null;
};

// The read-change-write of a user's `samlRoles` isn't atomic. The caller must
// not run two of them at once for the same user.

/**
 * Gives the user the role on the app. Assigns the user to the app first if
 * needed, marked `managedByP0`. Does nothing if the user has the role.
 */
export const addRole = async (
  { email, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> => {
  const okta = await connectOkta(target, logger).catch(rethrowMapped);
  const user = await findUser(okta, email).catch(rethrowMapped);
  if (user === null) {
    throw new ConnectorError({
      message: `Okta has no user with the email ${email}.`,
      payload: {},
      type: "object_not_found",
    });
  }
  const current = await okta.getAppUser(user.id).catch(rethrowMapped);
  if (current === null) {
    await okta
      .assignAppUser(user, { managedByP0: true, samlRoles: [role] })
      .catch(rethrowMapped);
    logger.info({ userId: user.id }, "assigned the user to the Okta app");
    return null;
  }
  if (current.samlRoles.includes(role)) return null;
  await okta
    .updateAppUser(user.id, { samlRoles: [...current.samlRoles, role] })
    .catch(rethrowMapped);
  logger.info({ userId: user.id }, "added the role to the Okta app user");
  return null;
};

/**
 * Takes the role away from the user on the app. Unassigns the user from the
 * app if P0 assigned them and no role is left. Does nothing if the user, or
 * their role, is already gone.
 */
export const removeRole = async (
  { email, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> => {
  const okta = await connectOkta(target, logger).catch(rethrowMapped);
  const user = await findUser(okta, email).catch(rethrowMapped);
  if (user === null) {
    logger.warn("Okta has no user with the email; nothing to remove");
    return null;
  }
  const current = await okta.getAppUser(user.id).catch(rethrowMapped);
  if (current === null) {
    logger.warn({ userId: user.id }, "the user isn't assigned to the Okta app");
    return null;
  }
  const remaining = current.samlRoles.filter((label) => label !== role);
  if (current.managedByP0 && remaining.length === 0) {
    await okta.unassignAppUser(user.id).catch(rethrowMapped);
    logger.info({ userId: user.id }, "unassigned the user from the Okta app");
    return null;
  }
  if (remaining.length === current.samlRoles.length) {
    logger.warn({ userId: user.id }, "the Okta app user doesn't have the role");
    return null;
  }
  await okta
    .updateAppUser(user.id, { samlRoles: remaining })
    .catch(rethrowMapped);
  logger.info({ userId: user.id }, "removed the role from the Okta app user");
  return null;
};
