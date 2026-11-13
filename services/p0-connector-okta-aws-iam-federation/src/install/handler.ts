import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { type App, app } from "../account.ts";
import {
  type OktaApp,
  type OktaClient,
  OktaError,
  connectOkta,
} from "../okta/client.ts";
import { toConnectorError } from "../okta/errors.ts";
import {
  AWS_APP_NAME,
  type InstallValidation,
  MANAGED_BY_P0,
} from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "app" | "configure" | "metadata" | "secret" | "token";

const failedAt = (step: Step) => (error: unknown) => {
  const mapped = toConnectorError(error);
  throw mapped instanceof ConnectorError
    ? new ConnectorError({
        ...mapped.data,
        payload: { ...mapped.data.payload, step },
      })
    : mapped;
};

/** `secret` and `token`: Okta as the service app. */
const connect = (input: App, logger: Logger) =>
  connectOkta(input, logger).catch((error: unknown) =>
    failedAt(error instanceof OktaError ? "token" : "secret")(error)
  );

/** `app`: the app is an active AWS Account Federation app that signs in with SAML. */
const getAwsApp = async (okta: OktaClient): Promise<OktaApp> => {
  const found = await okta.getApp().catch(failedAt("app"));
  const refuse = (message: string) => {
    throw new ConnectorError({
      message,
      payload: { name: found.name, signOnMode: found.signOnMode, step: "app" },
      type: "validation_error",
    });
  };
  if (found.name !== AWS_APP_NAME || found.signOnMode !== "SAML_2_0") {
    refuse(
      `The Okta app "${found.label}" isn't an AWS Account Federation app with SAML 2.0 sign-on. Give the ID of that app.`
    );
  }
  if (found.status !== "ACTIVE") {
    refuse(`The Okta app "${found.label}" isn't active. Activate it in Okta.`);
  }
  return found;
};

const ENTITY_ID = /entityID=["']([^"']+)["']/;

/** `metadata`: the entity ID in the app's SAML metadata. */
const getEntityId = async (okta: OktaClient): Promise<string> => {
  const metadata = await okta.getSamlMetadata().catch(failedAt("metadata"));
  const entityId = metadata.match(ENTITY_ID)?.[1];
  if (entityId === undefined) {
    throw new ConnectorError({
      message:
        "The Okta app's SAML metadata has no entity ID. Check the app's SAML settings in Okta.",
      payload: { step: "metadata" },
      type: "validation_error",
    });
  }
  return entityId;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the service app's private key.
 * 2. `token`: Okta gives the service app an access token with every scope.
 * 3. `app`: the app is an active AWS Account Federation app with SAML 2.0.
 * 4. `metadata`: the app's SAML metadata has an entity ID.
 *
 * Every check only reads.
 */
export const getInstallValidation = async (
  input: App,
  logger: Logger
): Promise<InstallValidation> => {
  const okta = await connect(input, logger);
  const { label } = await getAwsApp(okta);
  const entityId = await getEntityId(okta);
  return { entityId, label };
};

/**
 * Prepares the app for P0's assignments. Both writes can run again:
 *
 * - Adds `managedByP0` to the app user schema, so a revoke can tell an
 *   assignment P0 made.
 * - Sets `joinAllRoles`, so a user picks from the roles P0 assigns as well as
 *   the roles of their groups.
 *
 * Neither is undone when the integration is removed.
 */
export const applyConfiguration = async (
  input: App,
  logger: Logger
): Promise<null> => {
  const okta = await connect(input, logger);
  const found = await getAwsApp(okta);
  await okta.addAppUserProperties(MANAGED_BY_P0).catch(failedAt("configure"));
  const settings = found.settings.app ?? {};
  if (settings.joinAllRoles !== true) {
    await okta
      .replaceApp({
        ...found,
        settings: {
          ...found.settings,
          app: { ...settings, joinAllRoles: true },
        },
      })
      .catch(failedAt("configure"));
    logger.info("set joinAllRoles on the Okta app");
  }
  return null;
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    validation: router({
      get: procedure.input(app.parse).query(async ({ input, ctx }) => {
        const validation = await getInstallValidation(input, ctx.logger);
        ctx.logger.info(validation, "validated the Okta app");
        return validation;
      }),
    }),
    configuration: router({
      set: procedure
        .input(app.parse)
        .mutation(({ input, ctx }) => applyConfiguration(input, ctx.logger)),
    }),
  });
};
