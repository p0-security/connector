import type {
  TokenPolicyInput,
  TokenResources,
} from "../../cloudflare/cloudflare-api.ts";
import type { Resource } from "./definition.ts";

type Scope = Resource["scope"];

type ScopeDispatch<S extends Scope = Scope> = {
  /** The zone name the resource needs an id for. */
  zoneName(resource: Extract<Resource, { scope: S }>): string | undefined;
  /** What the policy grants under the account key, or `undefined` when the account has no such zone. */
  underAccount(
    resource: Extract<Resource, { scope: S }>,
    zoneIds: ReadonlyMap<string, string>
  ): TokenResources | "*" | undefined;
};

const accountDispatch: ScopeDispatch = {
  zoneName: () => undefined,
  underAccount: () => "*",
} satisfies ScopeDispatch<"account">;

const allZonesDispatch: ScopeDispatch = {
  zoneName: () => undefined,
  underAccount: () => ({ "com.cloudflare.api.account.zone.*": "*" }),
} satisfies ScopeDispatch<"all-zones">;

const zoneDispatch: ScopeDispatch = {
  zoneName: ({ zone }) => zone,
  underAccount: ({ zone }, zoneIds) => {
    const id = zoneIds.get(zone);
    return id === undefined
      ? undefined
      : { [`com.cloudflare.api.zone.${id}`]: "*" };
  },
} satisfies ScopeDispatch<"zone">;

const scopeDispatches: Record<Scope, ScopeDispatch> = {
  account: accountDispatch,
  "all-zones": allZonesDispatch,
  zone: zoneDispatch,
};

/** The zone names that `resources` grant on. */
export const zoneNamesOf = (resources: Resource[]): string[] =>
  resources.flatMap(
    (resource) => scopeDispatches[resource.scope].zoneName(resource) ?? []
  );

/**
 * One allow policy per resource, each nested under the account. A zone
 * resource whose name isn't in `zoneIds` makes no policy, and its name goes
 * in `missingZones`.
 *
 * @param zoneIds zone ids by zone name
 */
export const toTokenPolicies = (
  accountId: string,
  resources: Resource[],
  zoneIds: ReadonlyMap<string, string>
): { policies: TokenPolicyInput[]; missingZones: string[] } => {
  const policies: TokenPolicyInput[] = [];
  const missingZones: string[] = [];
  for (const resource of resources) {
    const dispatch = scopeDispatches[resource.scope];
    const granted = dispatch.underAccount(resource, zoneIds);
    if (granted === undefined) {
      missingZones.push(dispatch.zoneName(resource) ?? "");
      continue;
    }
    policies.push({
      effect: "allow",
      permission_groups: resource.groups.map((id) => ({ id })),
      resources: { [`com.cloudflare.api.account.${accountId}`]: granted },
    });
  }
  return { missingZones, policies };
};
