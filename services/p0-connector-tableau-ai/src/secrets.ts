import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretPayload,
  SecretRef,
} from "@p0security/secret-manager-client";
import { z } from "zod";

import type { ConnectedApp } from "./tableau/tableau-api.ts";

const adminApp = z.object({
  clientId: z.string(),
  secretId: z.string(),
  secret: z.string(),
});

/** Parses a secret value as JSON; returns `undefined` when it is not JSON. */
const parseJsonPayload = (value: SecretPayload): unknown => {
  try {
    return JSON.parse(
      typeof value === "string" ? value : value.toString("utf8")
    );
  } catch {
    return undefined;
  }
};

/** Reads the admin connected app that P0 uses to manage agent users and to
 * sign in as them. */
export const getAdminApp = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<ConnectedApp> => {
  const { value } = await secrets.getSecretValue({ ref });
  const parsed = adminApp.safeParse(parseJsonPayload(value));
  if (!parsed.success) {
    // The value is not logged or returned, because it holds the app's secret.
    throw new ConnectorError({
      type: "validation_error",
      message:
        'The Tableau admin connected app secret must be JSON of the form {"clientId": "...", "secretId": "...", "secret": "..."}',
      payload: {},
    });
  }
  return parsed.data;
};
