import {
  type ConnectorContext,
  type ResourceRootConnectorPrimitives,
  newConnectorRouter,
  newConnectorTRPC,
  newResourceRootRouter,
} from "@p0security/connector-core";

import { CUSTOM_APP_ACCESS, CUSTOM_APP_NAMESPACE } from "./constants.ts";
import { newMetadataRouter } from "./metadata.ts";
import type {
  CustomAppAccessSchema,
  CustomAppConnectorActions,
} from "./schema.ts";
import { CustomAppConnectorSpec } from "./spec.ts";

export type CustomAppConnectorParams = {
  /**
   * Builds the actions this connector implements, once per request. Taking a
   * factory rather than a plain object means anything request-scoped — a
   * target-system client carrying `ctx.logger`, a per-request connection — has
   * somewhere to live, and no connector has to restructure later to get it.
   */
  actions: (ctx: ConnectorContext) => CustomAppConnectorActions;
  /** Conventionally your own `package.json` version. */
  connectorVersion: string;
};

/**
 * Adapts the connector SDK's actions to the framework contract.
 */
const toResourceRootPrimitives = (
  actions: CustomAppConnectorActions
): ResourceRootConnectorPrimitives<CustomAppAccessSchema> => {
  return {
    getUser: async (context, user) => {
      if (await actions.userExists(context, user)) return user.principal;
      return null;
    },
    createUser: async (context, user) => {
      await actions.createUser(context, user);
      return user.principal;
    },
    setPoliciesForUser: async (context, _, user, policies) => {
      return await actions.setPoliciesForUser(context, user, policies);
    },
    deleteUser: async (context, _, user) => {
      return await actions.deleteUser(context, user);
    },
    validation: (context) => ({
      user: {
        userIsNamespacedByBody: async (userBody) =>
          await actions.validateUser(context, userBody),
        userIsNamespacedById: async () => true,
      },
    }),
    list: async (query) => {
      return await actions.list(query);
    },
  };
};

export const newCustomAppConnectorRouter = (
  params: CustomAppConnectorParams
) => {
  const t = newConnectorTRPC();

  return newConnectorRouter(
    CUSTOM_APP_NAMESPACE,
    t,
    {
      [CUSTOM_APP_ACCESS]: newResourceRootRouter(
        t,
        CustomAppConnectorSpec[CUSTOM_APP_ACCESS],
        (ctx) => toResourceRootPrimitives(params.actions(ctx))
      ),
    },
    t.router({}),
    newMetadataRouter(t, params.connectorVersion)
  );
};

export type CustomAppConnectorRouter = ReturnType<
  typeof newCustomAppConnectorRouter
>;
