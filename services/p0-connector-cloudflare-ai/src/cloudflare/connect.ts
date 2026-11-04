import type { Logger } from "@p0security/connector-core";

import type { Account } from "../account.ts";
import { readToken } from "../secrets.ts";
import { newCloudflareApi, newCloudflareClient } from "./cloudflare-api.ts";

/** Cloudflare on the account, as its install token, read now. */
export const connectCloudflare = async (
  { accountId, secret }: Account,
  logger: Logger
) => {
  const token = await readToken(secret, logger);
  return newCloudflareClient(newCloudflareApi({ logger, token }), accountId);
};
