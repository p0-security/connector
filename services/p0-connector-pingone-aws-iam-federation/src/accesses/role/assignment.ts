import { ConnectorError, type Logger } from "@p0security/connector-core";
import { z } from "zod";

import type { App } from "../../account.ts";
import {
  type PingOneClient,
  type PingOneUser,
  connectPingOne,
} from "../../pingone/client.ts";
import { toConnectorError } from "../../pingone/errors.ts";

/** One role label for one user, by the user's email, on the app. */
export type RoleAssignment = App & { email: string; role: string };

/** The one PingOne user with `email`, or `null` if there is none. */
const findUser = async (
  pingOne: PingOneClient,
  email: string
): Promise<PingOneUser | null> => {
  const users = await pingOne.findUsersByEmail(email);
  if (users.length > 1) {
    throw new ConnectorError({
      message: `More than one PingOne user has the email ${email}. Give the email to one user only.`,
      payload: { count: users.length },
      type: "validation_error",
    });
  }
  return users[0] ?? null;
};

const roleValues = z.array(z.string()).nullish();

/** The user's role labels. A user without any has no attribute. */
const rolesOf = (user: PingOneUser, roleAttribute: string): string[] => {
  const parsed = roleValues.safeParse(user[roleAttribute]);
  if (!parsed.success) {
    throw new ConnectorError({
      message: `The PingOne user attribute "${roleAttribute}" doesn't hold a list of text values. Make it a multi-valued text attribute in PingOne.`,
      payload: {},
      type: "validation_error",
    });
  }
  return parsed.data ?? [];
};

const rethrowMapped = (error: unknown): never => {
  throw toConnectorError(error);
};

/** PingOne's ID for the user with `email`, or `null` if there is none. */
export const findUserId = async (
  target: App,
  email: string,
  logger: Logger
): Promise<string | null> => {
  const pingOne = await connectPingOne(target, logger).catch(rethrowMapped);
  const user = await findUser(pingOne, email).catch(rethrowMapped);
  return user?.id ?? null;
};

// `PATCH` replaces the whole list, so the read-change-write isn't atomic. The
// caller must not run two of them at once for the same user.

/** Adds the role to the user's role attribute. Does nothing if the user has it. */
export const addRole = async (
  { email, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> => {
  const pingOne = await connectPingOne(target, logger).catch(rethrowMapped);
  const user = await findUser(pingOne, email).catch(rethrowMapped);
  if (user === null) {
    throw new ConnectorError({
      message: `PingOne has no user with the email ${email}.`,
      payload: {},
      type: "object_not_found",
    });
  }
  const current = rolesOf(user, target.roleAttribute);
  if (current.includes(role)) return null;
  await pingOne
    .setUserAttribute(user.id, target.roleAttribute, [...current, role])
    .catch(rethrowMapped);
  logger.info({ userId: user.id }, "added the role to the PingOne user");
  return null;
};

/**
 * Removes the role from the user's role attribute. Does nothing if the user,
 * or their role, is already gone.
 */
export const removeRole = async (
  { email, role, ...target }: RoleAssignment,
  logger: Logger
): Promise<null> => {
  const pingOne = await connectPingOne(target, logger).catch(rethrowMapped);
  const user = await findUser(pingOne, email).catch(rethrowMapped);
  if (user === null) {
    logger.warn("PingOne has no user with the email; nothing to remove");
    return null;
  }
  const current = rolesOf(user, target.roleAttribute);
  const remaining = current.filter((label) => label !== role);
  if (remaining.length === current.length) {
    logger.warn({ userId: user.id }, "the PingOne user doesn't have the role");
    return null;
  }
  await pingOne
    .setUserAttribute(user.id, target.roleAttribute, remaining)
    .catch(rethrowMapped);
  logger.info({ userId: user.id }, "removed the role from the PingOne user");
  return null;
};
