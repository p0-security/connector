import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretPayload,
  SecretRef,
} from "@p0security/secret-manager-client";
import { z } from "zod";

const adminKeys = z.object({ apiKey: z.string(), appKey: z.string() });

export type AdminKeys = z.infer<typeof adminKeys>;

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

/** Reads the admin API key and application key that P0 uses to create and
 * revoke grant tokens. */
export const getAdminKeys = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<AdminKeys> => {
  const { value } = await secrets.getSecretValue({ ref });
  const parsed = adminKeys.safeParse(parseJsonPayload(value));
  if (!parsed.success) {
    // The value is not logged or returned, because it holds the admin keys.
    throw new ConnectorError({
      type: "validation_error",
      message:
        'The Datadog admin keys secret must be JSON of the form {"apiKey": "...", "appKey": "..."}',
      payload: {},
    });
  }
  return parsed.data;
};
