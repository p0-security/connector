import type { PermissionGroup } from "../../cloudflare/cloudflare-api.ts";
import type { GroupScope } from "./definition.ts";

/**
 * Groups that let an agent take over the account: token management, account
 * settings, sign-in, billing and Access administration. Keyed on `id`,
 * because Cloudflare can rename a group.
 */
export const DENIED_GROUPS: Readonly<Record<string, string>> = {
  "5bc3f8b21c554832afc660159ab75fa4": "Account API Tokens Write",
  "1af1fa2adc104452b74a9a3364202f20": "Account Settings Write",
  d5812c023a5048b4882175a28952362d: "SCIM Provisioning",
  "901ca5e292584c6aa1b4cdb39248bb07": "SSO Connector Write",
  "50fc2f43318f40e4855a35d8de5bf643": "OAuth Client Write",
  "6c80e02421494afc9ae14414ed442632": "Billing Write",
  a1a6298e52584c8fb6313760a30c681e: "Zero Trust: Seats Write",
  bfe0d8686a584fa680f4c53b5eb0de6d:
    "Access: Organizations, Identity Providers, and Groups Write",
  aed5acd922ae4fa68560cf0094e3e517: "Access: Organizations Write",
  "5541aee5804a4850aa6d77351cc4a610": "Access: Identity Providers Write",
  f2f1e4d555854b8593912806eb459691: "Access: Groups Write",
  "1e13c5124ca64b72b1969a67e8829049": "Access: Apps and Policies Write",
  // The zone group of the same name.
  "959972745952452f8be2452be8cbb9f2": "Access: Apps and Policies Write",
  a1c0fec57cf94af79479a6d827fa518c: "Access: Service Tokens Write",
  bc783549a3a741aaa10556faf8b485bb: "Access: SCIM Population Write",
};

/** Groups of products that refuse account-owned tokens. */
export const UNSUPPORTED_GROUPS: Readonly<Record<string, string>> = {
  df1577df30ee46268f9470952d7b0cdf: "Intel Read",
  "92209474242d459690e2cdb1985eaa6c": "Intel Write",
  b415b70a4fd1412886f164451f20405c: "Page Rules Read",
  ed07f6c337da4195b4e72a1fb2c6bcae: "Page Rules Write",
  "9bb90620717647a39679e1d951f140d6": "Registrar Domains Read",
  "136d0be1ddc64eaf8516fa6994abfad4": "Registrar Domains Admin",
  "2e0d8adc461d4cf78651efa2dfbb237c": "Registrar Sandbox Domains Read",
  a649bfc3532148768b854e294a544425: "Registrar Sandbox Domains Admin",
  "5d78fd7895974fd0bdbbbb079482721b": "Turnstile Sites Read",
  "755c05aa014b4f9ab263aa80b8167bd8": "Turnstile Sites Write",
};

/** The Cloudflare scope of each group scope that a grant can use. */
const SCOPE_KEYS: Record<GroupScope, string> = {
  account: "com.cloudflare.api.account",
  zone: "com.cloudflare.api.account.zone",
};

const isHidden = (id: string) =>
  Object.hasOwn(DENIED_GROUPS, id) || Object.hasOwn(UNSUPPORTED_GROUPS, id);

/**
 * The groups an agent can request on `scope`. A group on any other scope,
 * such as one R2 bucket or one Worker script, is left out: a grant has no
 * resource for it.
 */
export const requestableGroups = (
  groups: PermissionGroup[],
  scope: GroupScope
) =>
  groups.filter(
    ({ id, scopes, is_selectable }) =>
      is_selectable !== false &&
      !isHidden(id) &&
      scopes.length > 0 &&
      scopes.every((key) => key === SCOPE_KEYS[scope])
  );
