import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { requestDeadline } from "../../jira/atlassian-call.ts";
import {
  createTokenSecret,
  deleteTokenSecret,
  findTokenSecret,
  readSecretString,
  writeTokenSecret,
} from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];

/**
 * Per-request token access. The "user" is the request's own token secret in
 * the vault project: created on grant, written with a copy of the leased pool
 * account's API key, and deleted on revoke. No other request reads or deletes
 * it.
 *
 * Atlassian's MCP server refuses a pool account's OAuth token but accepts its
 * API key, so the request gets the key itself. It is never returned or
 * logged. The key read keeps to the same budget as a Jira request (see
 * {@link requestDeadline}).
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => {
    const loggerFor = (context: RequestContext, secret: string) =>
      ctx.logger.child({ requestId: context.requestId, secret });

    return {
      validation: () => ({ user: null }),

      getUser: async (context, name) =>
        await findTokenSecret(
          context.vault.projectId,
          name,
          loggerFor(context, name)
        ),

      createUser: async (context, name) => {
        const logger = loggerFor(context, name);
        const created = await createTokenSecret(
          context.vault.projectId,
          name,
          logger
        );
        logger.info("created the request's token secret");
        return created;
      },

      deleteUser: async (context, name) => {
        const logger = loggerFor(context, name);
        await deleteTokenSecret(context.vault.projectId, name, logger);
        logger.info("deleted the request's token secret");
      },

      setPoliciesForUser: async (context, name, _user, policies) => {
        const logger = loggerFor(context, name);
        // On revoke P0 sends no policy, then deletes the secret.
        if (policies.length === 0) return;
        const [policy] = policies;
        if (policies.length > 1 || policy === undefined) {
          // A control-plane bug: one request leases one pool account.
          throw new ConnectorError({
            type: "unknown",
            message:
              "P0 asked the Jira connector for a token for more than one agent account, which it can't do. Contact support@p0.dev.",
            payload: {
              requestId: context.requestId,
              policies: policies.length,
            },
          });
        }
        const apiKey = await readSecretString(
          context.poolSecret,
          "the pool account's API key",
          logger,
          requestDeadline()
        );
        await writeTokenSecret(context.vault.projectId, name, apiKey, logger);
        logger.info(
          { accountId: policy.accountId },
          "copied the pool account's API key to the request's secret"
        );
      },

      // P0 looks accounts up through install.
      list: async () => [],
    };
  });
