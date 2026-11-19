import type { App } from "../account.ts";
import { callPingFederate } from "./http.ts";

export const AWS_PARTNER_ID = "urn:amazon:webservices";

export const metadataPath = () =>
  `/pf/federation_metadata.ping?PartnerSpId=${encodeURIComponent(AWS_PARTNER_ID)}`;

/** PingFederate answered with a status other than 200. */
export class MetadataStatusError extends Error {
  constructor(readonly status: number) {
    super(`PingFederate answered the metadata URL with ${status}`);
  }
}

/** Gets PingFederate's SAML metadata for its SP connection to AWS. */
export const getMetadata = async (
  target: Pick<App, "caCertificate" | "pingFederateUrl">
): Promise<string> => {
  const { status, body } = await callPingFederate(target, {
    method: "GET",
    path: metadataPath(),
  });
  if (status !== 200) throw new MetadataStatusError(status);
  return body;
};
