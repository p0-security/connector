import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";

import { assertAllowedEmail } from "../../allowlist.ts";
import { type ConnectHarbor, connectHarbor } from "../../harbor/client.ts";
import { callHarbor } from "../../harbor/errors.ts";
import { knownRoleOf } from "../../harbor/roles.ts";
import { duplicateEmail } from "../../refusals.ts";
import { hostOf, spec } from "./definition.ts";
import { setPolicies } from "./policies.ts";

/** The access's types, as its schemas infer them. */
export type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type ListerQuery = ResourceSchema["ListerQuery"];
type ListerResponse = ResourceSchema["ListerResponse"];

/**
 * The Harbor user whose email is the principal's: `[]` for none, or
 * `[{ key: <user id>, value: <username> }]`.
 *
 * The domain allowlist runs first, before the secret is read or Harbor is
 * called, so the connector looks up no one outside the domains it allows.
 * The client keeps only the users whose email equals the principal's,
 * ignoring case, out of Harbor's substring matches on every page. The user
 * list refuses a credential Harbor doesn't accept with a 401, so the lookup
 * proves the credential too.
 *
 * Two or more matches (emails that differ only in case, which Harbor's
 * unique constraint allows) is a refusal, worded as INT-231 words it: P0
 * can't tell which of them the principal is. No match is `[]`, and P0 words
 * that refusal, since it knows the instance's id and URL.
 */
const findMember = async (
  { context, email }: Extract<ListerQuery, { type: "member" }>,
  logger: Logger,
  connect: ConnectHarbor
): Promise<ListerResponse> => {
  assertAllowedEmail(email, logger);
  const host = hostOf(context);
  const harbor = await connect(context, logger);
  const users = await callHarbor(() => harbor.findUsersByEmail(email), host);
  if (users.length > 1) throw duplicateEmail({ host, email, users });
  return users.map(({ userId, username }) => ({
    key: String(userId),
    value: username,
  }));
};

/**
 * The instance's projects, by name: all of them, or with `project`, that one
 * project if it exists (A18, A18b). The admin user sees every project.
 *
 * The full listing proves the token before it pages `GET /projects` (the
 * client does), since Harbor answers a token it doesn't accept as an
 * anonymous caller, with the public projects. The single project is
 * `HEAD /projects?project_name=`, which refuses an anonymous caller.
 */
const listProjects = async (
  { context, project }: Extract<ListerQuery, { type: "project" }>,
  logger: Logger,
  connect: ConnectHarbor
): Promise<ListerResponse> => {
  const host = hostOf(context);
  const harbor = await connect(context, logger);
  if (project === undefined) {
    const projects = await callHarbor(() => harbor.listProjects(), host);
    return projects.map(({ name }) => ({ key: name, value: name }));
  }
  const exists = await callHarbor(() => harbor.projectExists(project), host);
  return exists ? [{ key: project, value: project }] : [];
};

/**
 * The role the user holds directly on the project: `[]` for none, or
 * `[{ key: <role>, value: <role> }]`. Only the user's own member row counts,
 * never a group's: P0 manages direct membership only (INT-232).
 *
 * `[]` means "held no direct role", which a grant records as the role to
 * restore at revoke, so nothing else may read as `[]`:
 * - a project that doesn't exist is the `project_gone` refusal, and the
 *   caller decides what that means (a revoke treats it as done);
 * - a row whose `role_id` isn't one of Harbor's five (Harbor stores any id a
 *   `PUT` sends) is a `validation_error` naming the id, since P0 can't
 *   record or restore a role it doesn't know.
 */
const findDirectRole = async (
  { context, project, userId }: Extract<ListerQuery, { type: "direct-role" }>,
  logger: Logger,
  connect: ConnectHarbor
): Promise<ListerResponse> => {
  const host = hostOf(context);
  const harbor = await connect(context, logger);
  const row = await callHarbor(
    // The schema holds `userId` to a canonical decimal, so it reads exactly.
    () => harbor.findDirectMember(project, Number(userId)),
    host
  );
  if (row === undefined) return [];
  const role = knownRoleOf(row, { host, project, userId });
  return [{ key: role, value: role }];
};

/**
 * The Harbor `projectRole` access: a direct role on one project, granted just
 * in time and taken back at expiry.
 *
 * Grants add or raise the user's direct role, and revokes put the prior
 * role back or remove the user (policies.ts).
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against a Harbor double.
 */
export const newProjectRolePrimitives = (
  logger: Logger,
  connect: ConnectHarbor
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // The user is Harbor's own numeric user id, which can't carry a P0
  // marker, so there's nothing to validate a user's namespace against.
  validation: () => ({ user: null }),
  /**
   * The user body's Harbor user id, without calling Harbor. P0 resolved it
   * from the principal's email at request time, and a grant checks it again
   * in `setPoliciesForUser`. It also runs at revoke, where nothing may stand
   * between P0 and taking access away. Never `undefined`: the framework's
   * `provisionUser` would then call `createUser`, which refuses. The
   * connector never calls `GET /users/{id}`, which needs `User: read`.
   */
  getUser: async (_context, { userId }) => userId,

  /**
   * Refuses. `getUser` always answers, so P0 never gets here, and the
   * connector never creates Harbor users: a person logs in to Harbor once.
   */
  createUser: async ({ requestId }) => {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Harbor connector to create a Harbor user, which it never does.",
      payload: { requestId },
    });
  },

  /**
   * A no-op, and this is load-bearing. P0's revoke calls it after
   * `setPoliciesForUser` has put the prior role back: removing the member
   * here would undo that.
   */
  deleteUser: async ({ requestId }, userId) => {
    logger.debug(
      { requestId, userId },
      "deleteUser is a no-op; the revoke puts the prior role back"
    );
  },

  /**
   * Leaves the user with one policy's role on its project: a grant adds or
   * raises their direct role, and a `null` role puts the prior role back or
   * removes them (policies.ts).
   */
  setPoliciesForUser: (context, userId, _user, policies) =>
    setPolicies({ connect, logger, context, userId, policies }),

  list: async (query) => {
    switch (query.type) {
      case "member":
        return await findMember(query, logger, connect);
      case "project":
        return await listProjects(query, logger, connect);
      case "direct-role":
        return await findDirectRole(query, logger, connect);
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newProjectRolePrimitives(ctx.logger, connectHarbor)
  );
