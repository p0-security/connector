import {
  type AnyConnectorTRPCInstance,
  type ConnectorContext,
  ConnectorError,
  type Logger,
  type ResourceRootSchemaOf,
  newResourceRootRouter,
} from "@p0security/connector";

import {
  type JiraClient,
  addRoleActor,
  confirmGone,
  ensureSchemeGrants,
  fetchProjectRoleIds,
  fetchSiteRoles,
  removeRoleActor,
  withJira,
} from "../../jira/jira-api.ts";
import {
  type P0Level,
  P0_ROLES,
  type RolePolicy,
  p0Level,
  spec,
} from "./definition.ts";
import { claimSite, otherTenantRole, p0SiteRoles } from "./p0-roles.ts";

type ResourceSchema = ResourceRootSchemaOf<typeof spec>;
type RequestContext = ResourceSchema["RequestContext"];
type UserBody = ResourceSchema["UserBody"];

/** Refuses a user body from a site other than the request's. */
const validateSameSite = (context: RequestContext, body: UserBody) => {
  if (body.cloudId !== context.site.cloudId) {
    throw new ConnectorError({
      type: "validation_error",
      message:
        "The account belongs to a different Jira site from the request's. Contact support@p0.dev.",
      payload: { requestId: context.requestId },
    });
  }
  return body.accountId;
};

/**
 * A team-managed project's request names one of its roles, or recorded one at
 * stage. Its roles are its own, so the site's roles don't apply to it.
 */
const isTeamManaged = (
  policies: readonly RolePolicy[],
  roleIds: readonly string[]
) => roleIds.length > 0 || policies.some((policy) => policy.type === "space");

const isNotFound = (error: unknown) =>
  error instanceof ConnectorError && error.data.type === "object_not_found";

/**
 * The id of the role a policy names, ready for the account to join.
 *
 * For one of P0's own roles, it takes the site role {@link claimSite}
 * claimed, then makes sure the project's permission scheme grants it its
 * level's permissions. For a team-managed project's role, the id must still
 * be one of the project's roles.
 */
const roleToKeep = async (
  jira: JiraClient,
  projectKey: string,
  projectRoleIds: ReadonlySet<string>,
  p0RoleIds: Record<P0Level, string>,
  policy: RolePolicy,
  logger: Logger
): Promise<string> => {
  if (policy.type === "space") {
    if (projectRoleIds.has(policy.roleId)) return policy.roleId;
    throw new ConnectorError({
      type: "object_not_found",
      message: `Jira project ${projectKey} no longer has the role this request asked for. Request access again, and pick one of the project's current roles.`,
      payload: { projectKey, roleId: policy.roleId },
    });
  }
  const id = p0RoleIds[policy.level];
  const added = await ensureSchemeGrants(
    jira,
    projectKey,
    id,
    P0_ROLES[policy.level].permissions
  );
  if (added > 0) {
    logger.info(
      { roleId: id, added },
      "granted P0's role its permissions in the project's permission scheme"
    );
  }
  return id;
};

/**
 * Leaves the account in exactly the roles `policies` names, on the request's
 * project: it adds the account to each named role, then removes it from
 * P0's own roles and the roles P0 recorded at stage, when they are outside
 * the set. In a company-managed project, P0's roles are those the project
 * lists by P0's names plus those the site lists by P0's names or description
 * prefix, since a project's list can leave out a site role and an admin can
 * rename one. Every grant first claims the site (see {@link claimSite}), so
 * it fails when another P0 organization manages the site's P0 roles, in a
 * team-managed project too. A revoke still removes the account then. Removing
 * an account from a role it doesn't hold succeeds, so the connector removes
 * from every candidate role without checking membership. A role P0 keeps must
 * exist on the project. One it removes from may be gone, and so may the
 * project when P0 keeps no role: an account can't hold a role on a deleted
 * project, so the call has nothing to remove. Jira also answers "not found"
 * to a caller without Administer Jira, so that counts only after
 * {@link confirmGone}.
 */
const setRoles = async (
  context: RequestContext,
  accountId: string,
  policies: readonly RolePolicy[],
  ctx: ConnectorContext
) => {
  const { site, projectKey, roleIds, requestId } = context;
  const logger = ctx.logger.child({ requestId, projectKey });
  await withJira(site, logger, async (jira) => {
    const ids = await fetchProjectRoleIds(jira, projectKey).catch(
      (error: unknown) => {
        if (policies.length === 0 && isNotFound(error)) return null;
        throw error;
      }
    );
    if (ids === null) {
      await confirmGone(jira, projectKey);
      logger.info(
        "the project is gone, so the account holds none of its roles"
      );
      return;
    }
    const projectRoleIds = new Set(ids.values());
    const teamManaged = isTeamManaged(policies, roleIds);
    const claimed =
      policies.length > 0 ? await claimSite(jira, site.tenantId) : undefined;
    const siteRoles =
      claimed?.siteRoles ?? (teamManaged ? [] : await fetchSiteRoles(jira));
    if (
      claimed === undefined &&
      otherTenantRole(siteRoles, site.tenantId) !== undefined
    ) {
      // Removing the account takes access away, so it goes ahead.
      logger.warn(
        "another P0 organization manages this site's P0 roles, so the connector only removes the account"
      );
    }
    const keep = new Set<string>();
    // A grant claimed the site above, so `claimed` is set whenever a policy
    // is. One policy at a time: every call shares the request's budget.
    if (claimed !== undefined) {
      for (const policy of policies) {
        keep.add(
          await roleToKeep(
            jira,
            projectKey,
            projectRoleIds,
            claimed.roleIds,
            policy,
            logger
          )
        );
      }
    }
    const drop = new Set(
      [
        ...p0Level.options.map((level) => ids.get(P0_ROLES[level].name)),
        ...(teamManaged ? [] : p0SiteRoles(siteRoles).map((role) => role.id)),
        ...roleIds,
      ].filter((id): id is string => id !== undefined && !keep.has(id))
    );
    for (const id of keep) await addRoleActor(jira, projectKey, id, accountId);
    for (const id of drop) {
      await removeRoleActor(jira, projectKey, id, accountId);
    }
    logger.info(
      { kept: keep.size, removed: drop.size },
      "set the account's project roles"
    );
  });
};

/**
 * Project role access. The "user" is an existing Atlassian account, which
 * the connector neither creates nor deletes: its policies are the roles it
 * holds on one project, P0's own in a company-managed project or the
 * project's own in a team-managed one.
 */
export const router = (t: AnyConnectorTRPCInstance) =>
  newResourceRootRouter<ResourceSchema>(t, spec, (ctx: ConnectorContext) => ({
    validation: () => ({ user: null }),

    getUser: async (context, body) => validateSameSite(context, body),

    createUser: async (context, body) => validateSameSite(context, body),

    // The account outlives the grant: revoking empties its roles instead.
    deleteUser: async () => {},

    setPoliciesForUser: async (context, accountId, _user, policies) =>
      await setRoles(context, accountId, policies, ctx),

    // P0 looks accounts and projects up through install.
    list: async () => [],
  }));
