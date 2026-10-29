import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
  throwAssertNever,
} from "@p0security/connector-core";
import {
  type SecretManagerProviderConfig,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

import { AGENT_KEY_PATTERN, newFacadeClient } from "../../salesforce/facade.ts";
import { getConsumerSecret } from "../../secrets.ts";
import { spec } from "./definition.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type OrgContext = ResourceSchema["ListerQuery"]["context"];

const secretManagerConfig = (
  secrets: OrgContext["secrets"]
): SecretManagerProviderConfig => {
  switch (secrets.manager) {
    case "aws":
      return { provider: "aws", region: secrets.region };
    case "gcp":
      return { provider: "gcp", projectId: secrets.projectId };
    default:
      throw throwAssertNever(secrets);
  }
};

const createSecretManager = async (context: OrgContext) => {
  try {
    return await createSecretManagerClient(
      secretManagerConfig(context.secrets)
    );
  } catch {
    throw new ConnectorError({
      type: "validation_error",
      message: "Invalid secret manager",
      payload: { manager: context.secrets.manager },
    });
  }
};

const facadeFor = async (context: OrgContext) => {
  const secretManager = await createSecretManager(context);
  const consumerSecret = await getConsumerSecret(
    secretManager,
    context.secrets.consumerSecretSecretId as SecretRef
  );
  return await newFacadeClient({
    domain: context.domain,
    consumerKey: context.consumerKey,
    consumerSecret,
  });
};

/**
 * Salesforce agent user lifecycle
 *
 * The abstract "user" of the resource-root paradigm is one API-only Salesforce
 * user, keyed by the agent key that P0 computes. Its policies are the
 * grantable permission sets that it holds. All changes go through the P0
 * package's facade, which touches only users in its agent role and profile.
 *
 * Salesforce cannot delete users, so `deleteUser` deactivates the user. A
 * deactivated user counts as missing, so the next grant reactivates it.
 *
 * The P0 control plane must serialize calls for the same user.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    validation: () => ({
      user: {
        userIsNamespacedByBody: async (agentKey) =>
          AGENT_KEY_PATTERN.test(agentKey),
        // The facade refuses a user outside its agent role and profile.
        userIsNamespacedById: async () => true,
      },
    }),

    getUser: async (context, agentKey) => {
      const facade = await facadeFor(context);
      const agent = await facade.findAgent(agentKey);
      ctx.logger.debug(
        { agentKey, requestId: context.requestId, found: !!agent },
        "looked up agent"
      );
      return agent?.active ? agent.userId : null;
    },

    createUser: async (context, agentKey) => {
      const facade = await facadeFor(context);
      const { userId } = await facade.upsertAgent(agentKey);
      ctx.logger.info(
        { agentKey, userId, requestId: context.requestId },
        "provisioned agent"
      );
      return userId;
    },

    deleteUser: async (context, userId) => {
      const facade = await facadeFor(context);
      await facade.retire(userId);
      ctx.logger.info(
        { userId, requestId: context.requestId },
        "retired agent"
      );
    },

    setPoliciesForUser: async (context, userId, _user, policies) => {
      const facade = await facadeFor(context);
      await facade.setGrants(userId, [...new Set(policies)].sort());
      ctx.logger.info(
        { userId, requestId: context.requestId, nGrants: policies.length },
        "set agent grants"
      );
    },

    list: async ({ type, context }) => {
      switch (type) {
        case "permission-set": {
          const facade = await facadeFor(context);
          const names = await facade.listGrantable();
          return names.map((name) => ({ key: name, value: name }));
        }
        default:
          throw throwAssertNever(type);
      }
    },
  }));
