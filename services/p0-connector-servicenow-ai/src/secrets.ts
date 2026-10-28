import { ConnectorError } from "@p0security/connector-core";
import type {
  SecretManagerClient,
  SecretRef,
} from "@p0security/secret-manager-client";
import { z } from "zod";

const InstallSecret = z.object({
  provisionerClientSecret: z.string().min(1),
  jwtClientSecret: z.string().min(1),
  signingKey: z.string().min(1),
});

export type InstallSecret = z.infer<typeof InstallSecret>;

/** Reads the install secret: both client secrets and the PEM signing key, as
 * one JSON object. */
export const getInstallSecret = async (
  secrets: SecretManagerClient,
  ref: SecretRef
): Promise<InstallSecret> => {
  const { value } = await secrets.getSecretValue({ ref });
  const text = typeof value === "string" ? value : value.toString("utf8");
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  const parsed = InstallSecret.safeParse(json);
  if (!parsed.success) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The ServiceNow install secret must be JSON with provisionerClientSecret, jwtClientSecret and signingKey",
      payload: {},
    });
  }
  // A PEM key saved as one line has "\n" where its line breaks were.
  return {
    ...parsed.data,
    signingKey: parsed.data.signingKey.replace(/\\n/g, "\n"),
  };
};
