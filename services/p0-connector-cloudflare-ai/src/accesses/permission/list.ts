import type { Logger } from "@p0security/connector-core";

import type { CloudflareClient } from "../../cloudflare/cloudflare-api.ts";
import { connectCloudflare } from "../../cloudflare/connect.ts";
import { toConnectorError } from "../../cloudflare/errors.ts";
import type { ListerQuery, ListerResponse } from "./definition.ts";
import { requestableGroups } from "./hidden.ts";

type ListerType = ListerQuery["type"];

type Lister<T extends ListerType = ListerType> = (
  cloudflare: CloudflareClient,
  query: Extract<ListerQuery, { type: T }>
) => Promise<ListerResponse>;

const policiesLister = (async (cloudflare, { scope }) =>
  requestableGroups(await cloudflare.listPermissionGroups(), scope).map(
    ({ id, name }) => ({ key: id, value: name })
  )) satisfies Lister<"policies">;

const zoneLister = (async (cloudflare) => [
  { key: "*", value: "All zones" },
  ...(await cloudflare.listZones()).map(({ name }) => ({
    key: name,
    value: name,
  })),
]) satisfies Lister<"zone">;

const listers: { [T in ListerType]: Lister<T> } = {
  policies: policiesLister,
  zone: zoneLister,
};

/** Answers a {@link ListerQuery} for the account in its context. */
export const list = async (
  logger: Logger,
  query: ListerQuery
): Promise<ListerResponse> => {
  const log = logger.child({ access: "permission", type: query.type });
  const lister = listers[query.type] as Lister;
  try {
    const cloudflare = await connectCloudflare(query.context, log);
    return await lister(cloudflare, query);
  } catch (error) {
    throw toConnectorError(error);
  }
};
