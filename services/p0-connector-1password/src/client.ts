import type { Client } from "@1password/sdk";

import packageJson from "../package.json" with { type: "json" };
import type { TokenSecret } from "./accesses/share/definition.ts";
import { type ServiceAccountToken, getServiceAccountToken } from "./secrets.ts";

/** The parts of the SDK's client the connector calls. */
export type OnePasswordClient = Pick<Client, "items" | "vaults">;

type CachedClient = {
  /** The version of the secret the client signed in with. */
  version: string;
  /** Pending while it signs in, so concurrent calls share it. */
  client: Promise<OnePasswordClient>;
};

// One per container, so a warm instance signs in once per secret version.
const clientCache = new Map<string, CachedClient>();

/**
 * One entry per pointer, in a fixed order. A service account token signs in
 * to one account, and each call names its vault, so the vault isn't part of
 * the key.
 */
const cacheKey = (tokenSecret: TokenSecret): string =>
  JSON.stringify([
    tokenSecret.manager,
    tokenSecret.secretId,
    tokenSecret.manager === "aws" ? tokenSecret.region : tokenSecret.projectId,
  ]);

const signIn = async (token: string): Promise<OnePasswordClient> => {
  // Loaded on first use: loading the SDK reads its 13 MB WebAssembly core
  // from disk, which a static import would make every test that loads the
  // router pay for.
  const { createClient } = await import("@1password/sdk");
  return createClient({
    auth: token,
    integrationName: "P0 Security",
    integrationVersion: packageJson.version ?? "unknown",
  });
};

/**
 * An SDK client signed in with `secret`, cached per (pointer, secret
 * version). A rotated secret signs in again on its next read, and a failed
 * sign-in is evicted, so the next call tries again.
 */
export const onePasswordClientFor = (
  tokenSecret: TokenSecret,
  { token, version }: ServiceAccountToken
): Promise<OnePasswordClient> => {
  const key = cacheKey(tokenSecret);
  const cached = clientCache.get(key);
  if (cached?.version === version) return cached.client;
  const entry: CachedClient = { version, client: signIn(token) };
  clientCache.set(key, entry);
  entry.client.catch(() => {
    if (clientCache.get(key) === entry) clientCache.delete(key);
  });
  return entry.client;
};

/**
 * Reads the token at `tokenSecret` and returns a client signed in with it:
 * what each call to the connector starts with.
 */
export const newOnePasswordClient = async (
  tokenSecret: TokenSecret
): Promise<OnePasswordClient> =>
  onePasswordClientFor(tokenSecret, await getServiceAccountToken(tokenSecret));
