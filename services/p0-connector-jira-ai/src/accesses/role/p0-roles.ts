import { ConnectorError } from "@p0security/connector";

import {
  type JiraClient,
  type SiteRole,
  fetchSiteRoles,
  findOrCreateSiteRole,
} from "../../jira/jira-api.ts";
import { type P0Level, P0_ROLES, p0Level } from "./definition.ts";

/**
 * The fixed start of the description on P0's site roles, which finds them
 * after a rename. The roles the connector creates add the P0 organization
 * after it. Kept short so the whole description, with a 128-character
 * organization id, stays under 255 characters.
 */
export const P0_ROLE_DESCRIPTION = "Made by P0 for approved AI agent access.";

/** The full description of a P0 role that `tenantId` manages. */
export const p0RoleDescription = (tenantId: string) =>
  `${P0_ROLE_DESCRIPTION} P0 organization: ${tenantId}`;

const TENANT_MARK = / P0 organization: ([A-Za-z0-9_-]{1,128})$/;

/** The P0 organization a role's description names, if any. */
export const tenantOf = (role: SiteRole): string | undefined =>
  role.description === undefined
    ? undefined
    : TENANT_MARK.exec(role.description)?.[1];

const P0_ROLE_NAMES: ReadonlySet<string> = new Set(
  p0Level.options.map((level) => P0_ROLES[level].name)
);

/**
 * P0's site roles: those with one of P0's fixed names, or a description that
 * starts with {@link P0_ROLE_DESCRIPTION}, so a role a Jira admin renamed
 * still counts.
 */
export const p0SiteRoles = (siteRoles: readonly SiteRole[]) =>
  siteRoles.filter(
    (role) =>
      P0_ROLE_NAMES.has(role.name) ||
      role.description?.startsWith(P0_ROLE_DESCRIPTION) === true
  );

/** A P0 role on the site that another P0 organization manages, if any. */
export const otherTenantRole = (
  siteRoles: readonly SiteRole[],
  tenantId: string
): SiteRole | undefined =>
  p0SiteRoles(siteRoles).find((role) => {
    const owner = tenantOf(role);
    return owner !== undefined && owner !== tenantId;
  });

/**
 * Refuses a site whose P0 roles another P0 organization manages.
 *
 * @throws ConnectorError (`validation_error`)
 */
export const validateSiteIsTenants = (
  siteRoles: readonly SiteRole[],
  tenantId: string
) => {
  const other = otherTenantRole(siteRoles, tenantId);
  if (other === undefined) return;
  throw new ConnectorError({
    type: "validation_error",
    message: `Another P0 organization already manages this Jira site's P0 roles, and only one organization can. Use that organization for this site. If it no longer uses the site, ask a Jira admin to delete P0's project roles, "P0 agent: read" and "P0 agent: write", under Settings > System > Project roles, then try again.`,
    payload: { roleId: other.id },
  });
};

/**
 * The id of P0's site role for `level`, ready for the account to join. It
 * finds the role by its fixed name, or creates it with this organization in
 * its description. P0 never adopts a role: one with P0's name is used only
 * when its description starts with {@link P0_ROLE_DESCRIPTION} and names this
 * organization, since every actor of the role gets what P0 grants it.
 *
 * @throws ConnectorError (`validation_error`) when another P0 organization
 * manages the role, such as one that created it in parallel, or when a role
 * with P0's name wasn't made by P0 for this organization
 */
export const claimP0Role = async (
  jira: JiraClient,
  level: P0Level,
  tenantId: string,
  siteRoles: readonly SiteRole[]
): Promise<string> => {
  const role = await findOrCreateSiteRole(
    jira,
    P0_ROLES[level].name,
    p0RoleDescription(tenantId),
    siteRoles
  );
  validateSiteIsTenants([role], tenantId);
  if (
    role.description?.startsWith(P0_ROLE_DESCRIPTION) !== true ||
    tenantOf(role) !== tenantId
  ) {
    throw new ConnectorError({
      type: "validation_error",
      message: `This Jira site already has a project role named "${role.name}" that P0 didn't make for this organization, so P0 won't use it. Ask a Jira admin to rename or delete that role under Settings > System > Project roles, then try again.`,
      payload: { roleId: role.id },
    });
  }
  return role.id;
};

/**
 * Claims the site for `tenantId` before anything changes on it: it refuses a
 * site where any P0 role names another P0 organization, then claims both of
 * P0's site roles (see {@link claimP0Role}), creating them where they are
 * missing. Install and every grant run it, so the first P0 organization to
 * verify a site holds it, even before its first grant.
 *
 * @returns The id of P0's role for each level, and the site's roles as Jira
 * listed them before any create
 * @throws ConnectorError (`validation_error`) when another P0 organization
 * manages the site's P0 roles
 */
export const claimSite = async (
  jira: JiraClient,
  tenantId: string
): Promise<{ roleIds: Record<P0Level, string>; siteRoles: SiteRole[] }> => {
  const siteRoles = await fetchSiteRoles(jira);
  validateSiteIsTenants(siteRoles, tenantId);
  const roleIds: Record<P0Level, string> = {
    read: await claimP0Role(jira, "read", tenantId, siteRoles),
    write: await claimP0Role(jira, "write", tenantId, siteRoles),
  };
  return { roleIds, siteRoles };
};
