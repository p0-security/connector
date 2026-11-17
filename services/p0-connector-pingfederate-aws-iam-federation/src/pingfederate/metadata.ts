import { get } from "node:https";

import type { App } from "../account.ts";

export const AWS_PARTNER_ID = "urn:amazon:webservices";

export const METADATA_TIMEOUT_MS = 10_000;

export const metadataUrl = (pingFederateUrl: string) =>
  `${pingFederateUrl}/pf/federation_metadata.ping?PartnerSpId=${encodeURIComponent(AWS_PARTNER_ID)}`;

/** PingFederate answered with a status other than 200. */
export class MetadataStatusError extends Error {
  constructor(readonly status: number) {
    super(`PingFederate answered the metadata URL with ${status}`);
  }
}

/**
 * Gets PingFederate's SAML metadata for its SP connection to AWS. Uses
 * `node:https`, because `fetch` takes no CA certificate.
 */
export const getMetadata = ({
  pingFederateUrl,
  caCertificate,
}: Pick<App, "caCertificate" | "pingFederateUrl">): Promise<string> =>
  new Promise((resolve, reject) => {
    const request = get(
      metadataUrl(pingFederateUrl),
      {
        timeout: METADATA_TIMEOUT_MS,
        ...(caCertificate === undefined ? {} : { ca: caCertificate }),
      },
      (response) => {
        if (response.statusCode !== 200) {
          response.resume();
          reject(new MetadataStatusError(response.statusCode ?? 0));
          return;
        }
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => (body += chunk));
        response.on("end", () => resolve(body));
        response.on("error", reject);
      }
    );
    request.on("timeout", () =>
      request.destroy(
        Object.assign(new Error("PingFederate didn't answer in time"), {
          code: "ETIMEDOUT",
        })
      )
    );
    request.on("error", reject);
  });
