import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { type App, app } from "../account.ts";
import {
  type PingOneClient,
  PingOneError,
  connectPingOne,
} from "../pingone/client.ts";
import { toConnectorError } from "../pingone/errors.ts";
import {
  type InstallValidation,
  PERSISTENT_NAME_ID_FORMAT,
  ROLE_ATTRIBUTE,
  SOURCE_IDENTITY_ATTRIBUTE,
  URI_NAME_FORMAT,
} from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "app" | "attribute" | "mappings" | "metadata" | "secret" | "token";

const failedAt = (step: Step) => (error: unknown) => {
  const mapped = toConnectorError(error);
  throw mapped instanceof ConnectorError
    ? new ConnectorError({
        ...mapped.data,
        payload: { ...mapped.data.payload, step },
      })
    : mapped;
};

const refusal = (step: Step, message: string, payload: object = {}) =>
  new ConnectorError({
    message,
    payload: { ...payload, step },
    type: "validation_error",
  });

/** `secret` and `token`: PingOne as the worker app. */
const connect = (input: App, logger: Logger) =>
  connectPingOne(input, logger).catch((error: unknown) =>
    failedAt(error instanceof PingOneError ? "token" : "secret")(error)
  );

/** `app`: the app is an enabled SAML app that sends a persistent NameID. */
const checkApp = async (pingOne: PingOneClient) => {
  const found = await pingOne.getApp().catch(failedAt("app"));
  const payload = { protocol: found.protocol, enabled: found.enabled };
  if (found.protocol !== "SAML") {
    throw refusal(
      "app",
      `The PingOne app "${found.name}" isn't a SAML app. Give the ID of the app that signs users in to AWS.`,
      payload
    );
  }
  if (!found.enabled) {
    throw refusal(
      "app",
      `The PingOne app "${found.name}" isn't enabled. Enable it in PingOne.`,
      payload
    );
  }
  if (found.nameIdFormat !== PERSISTENT_NAME_ID_FORMAT) {
    throw refusal(
      "app",
      `AWS refuses the PingOne app "${found.name}"'s sign-ins: its NameID format isn't persistent. Set the app's Subject NameID format to "${PERSISTENT_NAME_ID_FORMAT}" in PingOne.`,
      payload
    );
  }
  return found;
};

/**
 * `mappings`: the app sends the role attribute as `Role`, and the user's
 * email as `SourceIdentity` with the URI name format.
 */
const checkMappings = async (pingOne: PingOneClient, roleAttribute: string) => {
  const mappings = await pingOne
    .listAttributeMappings()
    .catch(failedAt("mappings"));
  const byName = (name: string) => mappings.find((m) => m.name === name);

  const roleValue = `\${user.${roleAttribute}}`;
  if (byName(ROLE_ATTRIBUTE)?.value !== roleValue) {
    throw refusal(
      "mappings",
      `The PingOne app doesn't map the user attribute "${roleAttribute}" to AWS's Role attribute. Add an attribute mapping with the name "${ROLE_ATTRIBUTE}" and the value "${roleValue}".`
    );
  }
  const sourceIdentity = byName(SOURCE_IDENTITY_ATTRIBUTE);
  if (
    sourceIdentity?.value !== "${user.email}" ||
    sourceIdentity.nameFormat !== URI_NAME_FORMAT
  ) {
    throw refusal(
      "mappings",
      `The PingOne app doesn't send the user's email as AWS's SourceIdentity. Add an attribute mapping with the name "${SOURCE_IDENTITY_ATTRIBUTE}", the value "\${user.email}" and the name format "${URI_NAME_FORMAT}".`
    );
  }
};

/**
 * `attribute`: the role attribute is a multi-valued text attribute with no
 * list or pattern of allowed values, which would refuse P0's values.
 */
const checkRoleAttribute = async (
  pingOne: PingOneClient,
  roleAttribute: string
) => {
  const attributes = await pingOne
    .listUserAttributes()
    .catch(failedAt("attribute"));
  const found = attributes.find(({ name }) => name === roleAttribute);
  if (found === undefined) {
    throw refusal(
      "attribute",
      `PingOne has no user attribute "${roleAttribute}". Add it as a multi-valued text attribute, or check the role attribute on the PingOne app in P0.`
    );
  }
  if (found.type !== "STRING" || found.multiValued !== true) {
    throw refusal(
      "attribute",
      `The PingOne user attribute "${roleAttribute}" isn't a multi-valued text attribute. Make it one in PingOne.`,
      { type: found.type, multiValued: found.multiValued }
    );
  }
  if (
    (found.enumeratedValues?.length ?? 0) > 0 ||
    (found.regexValidation ?? undefined) !== undefined
  ) {
    throw refusal(
      "attribute",
      `The PingOne user attribute "${roleAttribute}" has a list or pattern of allowed values, which refuses the roles P0 assigns. Remove them in PingOne.`
    );
  }
};

const ENTITY_ID = /entityID=["']([^"']+)["']/;

/** `metadata`: the entity ID in the app's SAML metadata. */
const getEntityId = async (pingOne: PingOneClient): Promise<string> => {
  const metadata = await pingOne.getSamlMetadata().catch(failedAt("metadata"));
  const entityId = metadata.match(ENTITY_ID)?.[1];
  if (entityId === undefined) {
    throw refusal(
      "metadata",
      "The PingOne app's SAML metadata has no entity ID. Check the app's SAML settings in PingOne."
    );
  }
  return entityId;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the worker app's client secret.
 * 2. `token`: PingOne gives the worker app an access token.
 * 3. `app`: the app is an enabled SAML app with a persistent NameID format.
 * 4. `mappings`: the app maps the role attribute to `Role`, and the email to
 *    `SourceIdentity`.
 * 5. `attribute`: the role attribute is multi-valued text with no allowed
 *    values.
 * 6. `metadata`: the app's SAML metadata has an entity ID.
 *
 * Every check only reads.
 */
export const getInstallValidation = async (
  input: App,
  logger: Logger
): Promise<InstallValidation> => {
  const pingOne = await connect(input, logger);
  const { name } = await checkApp(pingOne);
  await checkMappings(pingOne, input.roleAttribute);
  await checkRoleAttribute(pingOne, input.roleAttribute);
  const entityId = await getEntityId(pingOne);
  return { entityId, name };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    validation: router({
      get: procedure.input(app.parse).query(async ({ input, ctx }) => {
        const validation = await getInstallValidation(input, ctx.logger);
        ctx.logger.info(validation, "validated the PingOne app");
        return validation;
      }),
    }),
  });
};
