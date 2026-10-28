// Shaped after services/p0-connector-harbor/src/accesses/project-role/handler.ts:
// the resource-root primitives over a connect, with a user that is never
// created or deleted. The two accesses' handlers repeat each other on
// purpose, so project-role can be taken out without touching global-role.
import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootConnectorPrimitives,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector";

import { type ConnectArgoCd, connectArgoCd } from "../../argocd/client.ts";
import { readHeld, readRoles } from "../lines.ts";
import { spec } from "./definition.ts";
import { setPolicies } from "./policies.ts";

/** The access's types, as its schemas infer them. */
export type ResourceSchema = ResourceRootSchemaOf<typeof spec>;

type ListerQuery = ResourceSchema["ListerQuery"];
type ListerResponse = ResourceSchema["ListerResponse"];

/** Names as lister rows. */
const rowsOf = (names: readonly string[]): ListerResponse =>
  names.map((name) => ({ key: name, value: name }));

/**
 * The AppProjects the account can see, by name, with roles P0 can grant or
 * not. With `project`, that one project, or `[]`.
 */
const listProjects = async (
  { context, project }: Extract<ListerQuery, { type: "project" }>,
  logger: Logger,
  connect: ConnectArgoCd
): Promise<ListerResponse> => {
  const { projects } = await readRoles(connect, logger, context, {
    projects: true,
  });
  const names = projects.map(({ name }) => name);
  return rowsOf(
    project === undefined ? names : names.filter((name) => name === project)
  );
};

/**
 * The roles one AppProject defines, by name: `[]` for a project the account
 * can't see. With `role`, that one role, or `[]`.
 */
const listProjectRoles = async (
  { context, project, role }: Extract<ListerQuery, { type: "role" }>,
  logger: Logger,
  connect: ConnectArgoCd
): Promise<ListerResponse> => {
  const { projects } = await readRoles(connect, logger, context, {
    projects: true,
  });
  const roles = projects.find(({ name }) => name === project)?.roles ?? [];
  return rowsOf(
    role === undefined ? roles : roles.filter((name) => name === role)
  );
};

/**
 * Whether the user with `email` holds the project's role already: `[]`, or
 * the role. The domain allowlist runs first, before the secret is read or
 * Argo CD is called.
 */
const listHeld = async (
  { context, email, project, role }: Extract<ListerQuery, { type: "held" }>,
  logger: Logger,
  connect: ConnectArgoCd
): Promise<ListerResponse> => {
  const held = await readHeld(connect, logger, context, email, {
    kind: "project",
    project,
    role,
  });
  return rowsOf(held ? [role] : []);
};

/**
 * The Argo CD `projectRole` access: a role an AppProject already defines,
 * granted just in time and taken back at expiry, as one
 * `g, <email>, proj:<project>:<role>` line in `policy.p0.csv`.
 *
 * It rests on an undocumented Argo CD behaviour, that a global `g` line to
 * `proj:<project>:<role>` grants the project's role (spec assumption 5). If
 * live testing disproves it, this access is removed.
 *
 * Exported separately from {@link router} so the primitives can be driven
 * against an Argo CD double.
 */
export const newProjectRolePrimitives = (
  logger: Logger,
  connect: ConnectArgoCd
): ResourceRootConnectorPrimitives<ResourceSchema> => ({
  // The user is their SSO email, which can't carry a P0 marker, so there's
  // nothing to validate a user's namespace against.
  validation: () => ({ user: null }),

  /**
   * The user body's email, without calling Argo CD. Never `null`: the
   * framework's `provisionUser` would then call `createUser`, which refuses.
   */
  getUser: async (_context, { email }) => email,

  /** Refuses: `getUser` always answers, and the connector creates no one. */
  createUser: async ({ requestId }) => {
    throw new ConnectorError({
      type: "unknown",
      message:
        "P0 asked the Argo CD connector to create an Argo CD user, which it never does.",
      payload: { requestId },
    });
  },

  /** A no-op: there is no user to delete. The revoke removed the line. */
  deleteUser: async ({ requestId }) => {
    logger.debug(
      { requestId },
      "deleteUser is a no-op; the revoke removed the line"
    );
  },

  /** Adds P0's line for the project role, or with a `null` role removes it. */
  setPoliciesForUser: (context, userId, _user, policies) =>
    setPolicies({ connect, logger, context, userId, policies }),

  list: async (query) => {
    switch (query.type) {
      case "project":
        return await listProjects(query, logger, connect);
      case "role":
        return await listProjectRoles(query, logger, connect);
      case "held":
        return await listHeld(query, logger, connect);
      default:
        throw throwAssertNever(query);
    }
  },
});

export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) =>
    newProjectRolePrimitives(ctx.logger, connectArgoCd)
  );
