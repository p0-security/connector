import {
  type SecretManagerProviderConfig,
  type SecretRef,
  createSecretManagerClient,
} from "@p0security/connector-secret-manager-client";

export const getGithubPrivateKey = async (
  config: SecretManagerProviderConfig,
  secretName: SecretRef
) => {
  const secrets = await createSecretManagerClient(config);
  const { value } = await secrets.getSecretValue({
    ref: secretName,
  });
  // Normalize keys stored with escaped "\n" (a common way PEM keys get saved as
  // a single-line secret) back to real newlines; a genuine multi-line PEM is
  // unaffected since its newlines are real 0x0A bytes, not the two-char "\n".
  const rawKey = typeof value === "string" ? value : value.toString("utf8");
  return rawKey.replace(/\\n/g, "\n");
};

export type SecretFor = ReturnType<typeof getGithubPrivateKey>;
