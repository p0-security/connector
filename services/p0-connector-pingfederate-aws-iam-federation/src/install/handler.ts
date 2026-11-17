import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { type App, app } from "../account.ts";
import { type Server, toConnectorError } from "../errors.ts";
import { type Directory, connectDirectory } from "../ldap/client.ts";
import {
  AWS_PARTNER_ID,
  MetadataStatusError,
  getMetadata,
} from "../pingfederate/metadata.ts";
import { readBindPassword } from "../secrets.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "attribute" | "baseDn" | "bind" | "metadata" | "secret";

const failedAt =
  (step: Step, server: Server = "the user store") =>
  (error: unknown): never => {
    const mapped = toConnectorError(error, server);
    throw mapped instanceof ConnectorError
      ? new ConnectorError({
          ...mapped.data,
          payload: { ...mapped.data.payload, step },
        })
      : mapped;
  };

const refusal = (
  step: Step,
  message: string,
  type: "upstream_unavailable" | "validation_error" = "validation_error"
) => new ConnectorError({ message, payload: { step }, type });

/** `baseDn`: the base DN is an entry. */
const checkBaseDn = async (directory: Directory, baseDn: string) => {
  const exists = await directory.entryExists(baseDn).catch(failedAt("baseDn"));
  if (!exists) {
    throw refusal(
      "baseDn",
      `The user store has no entry "${baseDn}". Check the base DN on the PingFederate app in P0.`
    );
  }
};

/**
 * `attribute`: the user store's schema has the role attribute, and it takes
 * more than one value.
 */
const checkRoleAttribute = async (
  directory: Directory,
  roleAttribute: string
) => {
  const found = await directory
    .findAttributeType(roleAttribute)
    .catch(failedAt("attribute"));
  if (found === undefined) {
    throw refusal(
      "attribute",
      `The user store's schema has no attribute "${roleAttribute}". Add it as a multi-valued text attribute, or check the role attribute on the PingFederate app in P0.`
    );
  }
  if (found.singleValued) {
    throw refusal(
      "attribute",
      `The user store's attribute "${roleAttribute}" takes only one value. A user can have more than one AWS role, so make it multi-valued.`
    );
  }
};

const ENTITY_ID = /entityID=["']([^"']+)["']/;

/** `metadata`: the entity ID in PingFederate's SAML metadata for AWS. */
const getEntityId = async (input: App): Promise<string> => {
  const metadata = await getMetadata(input).catch((error: unknown) => {
    if (error instanceof MetadataStatusError) {
      throw refusal(
        "metadata",
        `PingFederate answered the metadata URL with ${error.status}. Check the PingFederate URL on the app in P0, and that PingFederate has an SP connection with the partner "${AWS_PARTNER_ID}".`,
        error.status >= 500 ? "upstream_unavailable" : "validation_error"
      );
    }
    return failedAt("metadata", "PingFederate")(error);
  });
  const entityId = metadata.match(ENTITY_ID)?.[1];
  if (entityId === undefined) {
    throw refusal(
      "metadata",
      "PingFederate's SAML metadata has no entity ID. Check the PingFederate URL on the app in P0."
    );
  }
  return entityId;
};

/**
 * Install validation, in order, each failure thrown with its step:
 *
 * 1. `secret`: the connector can read the bind account's password.
 * 2. `bind`: the bind account can bind to the user store over LDAPS.
 * 3. `baseDn`: the base DN is an entry.
 * 4. `attribute`: the schema has the role attribute, multi-valued.
 * 5. `metadata`: PingFederate's SAML metadata for AWS has an entity ID.
 *
 * Every check only reads.
 */
export const getInstallValidation = async (
  input: App,
  logger: Logger
): Promise<InstallValidation> => {
  const password = await readBindPassword(input.bindPassword, logger).catch(
    failedAt("secret")
  );
  const directory = await connectDirectory(input, password).catch(
    failedAt("bind")
  );
  try {
    await checkBaseDn(directory, input.baseDn);
    await checkRoleAttribute(directory, input.roleAttribute);
  } finally {
    await directory.close();
  }
  return { entityId: await getEntityId(input) };
};

export const router = (t: AnyConnectorTRPCInstance) => {
  const { router } = t;
  const procedure = withRouteLogging(t.procedure);

  return router({
    validation: router({
      get: procedure.input(app.parse).query(async ({ input, ctx }) => {
        const validation = await getInstallValidation(input, ctx.logger);
        ctx.logger.info(validation, "validated the PingFederate app");
        return validation;
      }),
    }),
  });
};
