import { ConnectorError } from "@p0security/connector-core";

import type { IdentityTokenSource } from "./source.ts";

/** The metadata server, as `packages/gcloud/src/helpers/gcloud-metadata.ts` names it. */
const METADATA_URL = "http://metadata.google.internal/computeMetadata/v1";

const METADATA_TIMEOUT_MS = 2_000;

// A JWT: three base64url parts. Nothing else is taken as one.
const JWT = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

/** The metadata server's answer and its body, or `upstream_unavailable` when it can't be reached. */
const askMetadataServer = async (
  audience: string
): Promise<{ response: Response; text: string }> => {
  const query = new URLSearchParams({ audience, format: "full" });
  try {
    const response = await fetch(
      `${METADATA_URL}/instance/service-accounts/default/identity?${query.toString()}`,
      {
        headers: { "Metadata-Flavor": "Google" },
        redirect: "error",
        signal: AbortSignal.timeout(METADATA_TIMEOUT_MS),
      }
    );
    return { response, text: (await response.text()).trim() };
  } catch (error) {
    throw new ConnectorError({
      type: "upstream_unavailable",
      message:
        "The connector couldn't reach the Google metadata server for its identity token. Check that it runs on Cloud Run, then retry.",
      payload: { error: error instanceof Error ? error.name : "UnknownError" },
    });
  }
};

/**
 * Mints a Google ID token for the Cloud Run service's own account, from the
 * metadata server. `format=full` is what Tailscale's own client sends, so
 * the claims are the ones its issuer check was written against.
 */
export const gcpIdentityToken: IdentityTokenSource = async (audience) => {
  const { response, text } = await askMetadataServer(audience);
  if (!response.ok) {
    throw new ConnectorError({
      type:
        response.status >= 500
          ? "upstream_unavailable"
          : "insufficient_privileges",
      message: `The Google metadata server didn't mint an identity token for the connector's service account (${response.status}). Check the Cloud Run service's service account.`,
      payload: { status: response.status },
    });
  }
  if (!JWT.test(text)) {
    throw new ConnectorError({
      type: "unknown",
      message: "The Google metadata server returned no identity token.",
      payload: {},
    });
  }
  return text;
};
