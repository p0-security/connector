import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  type ResourceRootParsers,
  type ResourceRootSchema,
  newResourceRootRouter,
} from "@p0security/connector-core";

import {
  disableUserStatement,
  findAgent,
  mintAgent,
  removeAgent,
} from "../agent.ts";
import {
  AGENT_NAME_PATTERN,
  type ListerQuery,
  type ListerResponse,
  type RequestContext,
} from "../context.ts";
import { listFor } from "../listing/lister.ts";
import { createSecretManager, signInFor } from "../secrets.ts";
import { type SnowflakeSession, withSnowflake } from "../snowflake/client.ts";

/** The schema both access types share; only the policy differs. */
export type AgentSchema<Policy extends ResourceRootSchema["Policy"]> = {
  UserBody: string;
  UserId: string;
  Policy: Policy;
  ListerQuery: ListerQuery;
  ListerResponse: ListerResponse;
  RequestContext: RequestContext;
};

/** Grants one policy's access to the wrapper role `role`. */
export type GrantPolicy<Policy> = (
  session: SnowflakeSession,
  role: string,
  policy: Policy
) => Promise<void>;

/**
 * Snowflake agent identity lifecycle, shared by both access types.
 *
 * The abstract "user" of the resource-root paradigm is a minted
 * `SERVICE_AGENT` user named `P0_AGENT_<request id>`, with a wrapper role of
 * the same name. P0 chooses the name; the connector refuses any other.
 *
 * - `getUser` finds the user by exact name.
 * - `createUser` mints the role, the user and its token ({@link mintAgent}).
 * - `setPoliciesForUser` grants each policy's access to the wrapper role.
 *   With no policies (the revoke path) it disables the user, so access ends
 *   before anything is dropped.
 * - `deleteUser` drops the user, the role and the secret ({@link removeAgent}).
 *
 * Each identity serves one request, so its policies never shrink except to
 * none on revoke, and grants are only ever added. The user and its token
 * also expire on their own after the grant's length in whole days.
 *
 * The P0 control plane must serialize calls for the same user.
 */
export const newAgentAccessRouter = <
  Policy extends ResourceRootSchema["Policy"],
>(
  t: AnyConnectorTRPCInstance,
  spec: ResourceRootParsers<AgentSchema<Policy>>,
  grant: GrantPolicy<Policy>
) =>
  newResourceRootRouter<AgentSchema<Policy>>(
    t,
    spec,
    (ctx: ConnectorContext) => {
      /** Runs `use` with a Snowflake session as the connector, and the
       * install's secret manager. */
      const withAccount = async <T>(
        context: RequestContext,
        use: (
          session: SnowflakeSession,
          secrets: Awaited<ReturnType<typeof createSecretManager>>
        ) => Promise<T>
      ) => {
        const secrets = await createSecretManager(context);
        const signIn = await signInFor(context, secrets);
        const logger = ctx.logger.child({ requestId: context.requestId });
        return await withSnowflake(signIn, logger, (session) =>
          use(session, secrets)
        );
      };

      return {
        validation: () => ({
          user: {
            userIsNamespacedByBody: async (name) =>
              AGENT_NAME_PATTERN.test(name),
            userIsNamespacedById: async (name) => AGENT_NAME_PATTERN.test(name),
          },
        }),

        getUser: async (context, name) => {
          const logger = ctx.logger.child({
            user: name,
            requestId: context.requestId,
          });
          return await withAccount(context, (session, secrets) =>
            findAgent(session, secrets, logger, context, name)
          );
        },

        createUser: async (context, name) => {
          const logger = ctx.logger.child({
            user: name,
            requestId: context.requestId,
          });
          return await withAccount(context, (session, secrets) =>
            mintAgent(session, secrets, logger, context, name)
          );
        },

        deleteUser: async (context, name) => {
          const logger = ctx.logger.child({
            user: name,
            requestId: context.requestId,
          });
          await withAccount(context, (session, secrets) =>
            removeAgent(session, secrets, context, name)
          );
          logger.info("removed agent user, role and secret");
        },

        setPoliciesForUser: async (context, name, _user, policies) => {
          const logger = ctx.logger.child({
            user: name,
            requestId: context.requestId,
          });
          await withAccount(context, async (session) => {
            if (policies.length === 0) {
              await session.execute(disableUserStatement(name));
              logger.info("disabled agent user; no policies remain");
              return;
            }
            for (const policy of policies) await grant(session, name, policy);
            logger.info({ nPolicies: policies.length }, "granted policies");
          });
        },

        list: async ({ type, context }) => {
          const logger = ctx.logger.child({ account: context.account });
          const secrets = await createSecretManager(context);
          const signIn = await signInFor(context, secrets);
          return await withSnowflake(signIn, logger, (session) =>
            listFor(session, type)
          );
        },
      };
    }
  );
