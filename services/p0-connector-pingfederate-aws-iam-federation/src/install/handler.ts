import {
  type AnyConnectorTRPCInstance,
  ConnectorError,
  type Logger,
  withRouteLogging,
} from "@p0security/connector-core";

import { type App, app } from "../account.ts";
import { toConnectorError } from "../errors.ts";
import {
  AWS_PARTNER_ID,
  MetadataStatusError,
  getMetadata,
} from "../pingfederate/metadata.ts";
import {
  SCIM_EXTENSION,
  type Scim,
  ScimStatusError,
  scimClient,
} from "../pingfederate/scim.ts";
import { readScimPassword } from "../secrets.ts";
import type { InstallValidation } from "./definition.ts";

/** The checks, by the name a failure reports in `payload.step`. */
type Step = "attribute" | "metadata" | "scim" | "secret";

const failedAt =
  (step: Step) =>
  (error: unknown): never => {
    const mapped = toConnectorError(error);
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

// An address no user has: the search checks the credentials and the filter.
const PROBE_EMAIL = "install-check@p0.dev";

/** `scim`: the credentials work, and PingFederate can find users by work email. */
const checkScim = async (scim: Scim) => {
  await scim.findUsers(PROBE_EMAIL).catch((error: unknown) => {
    if (
      error instanceof ScimStatusError &&
      error.status === 400 &&
      error.detail?.includes("emails.work.value")
    ) {
      throw refusal(
        "scim",
        `PingFederate can't find users by "emails.work.value" (${error.detail}). Map the user's email to "emails.work.value" in the SCIM IdP connection's Read Users mapping.`
      );
    }
    return failedAt("scim")(error);
  });
};

/**
 * `attribute`: PingFederate's custom SCIM schema has the role attribute, it
 * takes more than one value, and SCIM can write it.
 */
const checkRoleAttribute = async (scim: Scim, roleAttribute: string) => {
  const attributes = await scim
    .getExtensionAttributes()
    .catch(failedAt("attribute"));
  // SCIM attribute names ignore case (RFC 7643).
  const wanted = roleAttribute.toLowerCase();
  const found = attributes?.find(({ name }) => name.toLowerCase() === wanted);
  if (found === undefined) {
    throw refusal(
      "attribute",
      `PingFederate's SCIM connection has no custom attribute "${roleAttribute}" in "${SCIM_EXTENSION}". Add it as a multi-valued string attribute, or check the role attribute on the PingFederate app in P0.`
    );
  }
  if (!found.multiValued) {
    throw refusal(
      "attribute",
      `PingFederate's SCIM attribute "${roleAttribute}" takes only one value. A user can have more than one AWS role, so make it multi-valued.`
    );
  }
  if (found.mutability.toLowerCase() !== "readwrite") {
    throw refusal(
      "attribute",
      `PingFederate's SCIM attribute "${roleAttribute}" is ${found.mutability}. Make it read-write.`
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
    return failedAt("metadata")(error);
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
 * 1. `secret`: the connector can read the SCIM password.
 * 2. `scim`: PingFederate accepts the SCIM credentials and finds users by work email.
 * 3. `attribute`: the custom SCIM schema has the role attribute, multi-valued and read-write.
 * 4. `metadata`: PingFederate's SAML metadata for AWS has an entity ID.
 *
 * Every check only reads.
 */
export const getInstallValidation = async (
  input: App,
  logger: Logger
): Promise<InstallValidation> => {
  const password = await readScimPassword(input.scimPassword, logger).catch(
    failedAt("secret")
  );
  const scim = scimClient(input, password);
  await checkScim(scim);
  await checkRoleAttribute(scim, input.roleAttribute);
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
