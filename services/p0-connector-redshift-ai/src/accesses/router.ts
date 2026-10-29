// shape copied from services/p0-connector-snowflake-ai/src/accesses/router.ts
import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type ResourceRootParsers,
  type ResourceRootSchema,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { createAgent, dropAgent, findAgent, revokeAgent } from "../agent.ts";
import type {
  ListerQuery,
  ListerResponse,
  RequestContext,
} from "../context.ts";
import { listFor } from "../listing/lister.ts";
import {
  type RedshiftSession,
  newRedshiftSession,
} from "../redshift/data-api.ts";
import { AGENT_USER_PATTERN } from "../sql.ts";

/** The schema both access types share; the policy and the request context
 * differ. */
export type AgentSchema<
  Policy extends ResourceRootSchema["Policy"],
  Context extends RequestContext,
> = {
  UserBody: string;
  UserId: string;
  Policy: Policy;
  ListerQuery: ListerQuery;
  ListerResponse: ListerResponse;
  RequestContext: Context;
};

/** What one access type adds to the agent's lifecycle. */
export type AgentAccess<Policy, Context extends RequestContext> = {
  /** Grants every policy to `user`. It can run again after a partial
   * failure, so each step must check, or allow, what an earlier run did. */
  grant: (
    session: RedshiftSession,
    context: Context,
    user: string,
    policies: Policy[]
  ) => Promise<void>;
  /** The roles P0 creates for this grant. Revoke empties them, and delete
   * drops them after the user. */
  privilegeRoles: (context: Context) => string[];
};

/**
 * Redshift agent lifecycle, shared by both access types.
 *
 * The resource-root "user" is the database user `IAMR:p0-agent-<id>`, which
 * the grant's IAM role signs in as. P0 chooses the name; the connector
 * refuses any other.
 *
 * - `getUser` finds the user by exact name.
 * - `createUser` creates it with no password.
 * - `setPoliciesForUser` grants the access type's policies. With no policies
 *   (the revoke path) it runs {@link revokeAgent}.
 * - `deleteUser` drops the user and its privilege roles.
 *
 * Each user serves one request, so its policies never shrink except to none
 * on revoke. The P0 control plane must serialize calls for the same user.
 */
export const newAgentAccessRouter = <
  Policy extends ResourceRootSchema["Policy"],
  Context extends RequestContext,
>(
  t: AnyConnectorTRPCInstance,
  spec: ResourceRootParsers<AgentSchema<Policy, Context>>,
  access: AgentAccess<Policy, Context>
) =>
  newResourceRootRouter<AgentSchema<Policy, Context>>(
    t,
    spec,
    (ctx: ConnectorContext) => {
      const sessionFor = (context: Context, user?: string) => {
        const logger = ctx.logger.child({
          requestId: context.requestId,
          target: context.target.name,
          ...(user ? { user } : {}),
        });
        return { logger, session: newRedshiftSession(context, logger) };
      };

      return {
        validation: () => ({
          user: {
            userIsNamespacedByBody: async (name) =>
              AGENT_USER_PATTERN.test(name),
            userIsNamespacedById: async (name) => AGENT_USER_PATTERN.test(name),
          },
        }),

        getUser: async (context, user) =>
          await findAgent(sessionFor(context, user).session, user),

        createUser: async (context, user) => {
          const { session, logger } = sessionFor(context, user);
          await createAgent(session, user);
          logger.info("created agent user");
          return user;
        },

        deleteUser: async (context, user) => {
          const { session, logger } = sessionFor(context, user);
          await dropAgent(session, user, access.privilegeRoles(context));
          logger.info("dropped agent user and privilege roles");
        },

        setPoliciesForUser: async (context, user, _body, policies) => {
          const { session, logger } = sessionFor(context, user);
          if (policies.length === 0) {
            await revokeAgent(
              session,
              logger,
              context,
              user,
              access.privilegeRoles(context)
            );
            return;
          }
          await access.grant(session, context, user, policies);
          logger.info({ nPolicies: policies.length }, "granted policies");
        },

        list: async ({ type, context }) => {
          const logger = ctx.logger.child({ target: context.target.name });
          return await listFor(
            newRedshiftSession(context, logger),
            logger,
            type
          );
        },
      };
    }
  );
