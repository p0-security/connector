import {
  type AnyConnectorTRPCInstance,
  type Logger,
  withRouteLogging,
} from "@p0security/connector";

import { claimSite } from "../accesses/role/p0-roles.ts";
import {
  fetchAccountIdByEmail,
  fetchProject,
  fetchProjectRoleIds,
  hasJiraAdmin,
  withJira,
} from "../jira/jira-api.ts";
import {
  type AccountLookup,
  type AccountQuery,
  type ProjectLookup,
  type ProjectQuery,
  type SiteLookup,
  type SiteQuery,
  accountQuery,
  projectQuery,
  siteQuery,
} from "./definition.ts";

/**
 * Whether the site's admin account holds Administer Jira. When it does, the
 * lookup claims the site for this P0 organization (see {@link claimSite}),
 * so a second organization can't verify it.
 *
 * @throws ConnectorError (`validation_error`) when another P0 organization
 * manages the site's P0 roles
 */
export const fetchSiteFacts = async (
  { site }: SiteQuery,
  logger: Logger
): Promise<SiteLookup> =>
  await withJira(site, logger, async (jira) => {
    const jiraAdmin = await hasJiraAdmin(jira);
    if (jiraAdmin) await claimSite(jira, site.tenantId);
    return { jiraAdmin };
  });

/** The account behind an email, as the site's admin account sees it. */
export const fetchAccount = async (
  { site, email }: AccountQuery,
  logger: Logger
): Promise<AccountLookup> => ({
  accountId: await withJira(site, logger, (jira) =>
    fetchAccountIdByEmail(jira, email)
  ),
});

/**
 * Whether a project is company-managed (Jira's `classic` style) or
 * team-managed, and every role it lists, by id and name.
 */
export const fetchProjectFacts = async (
  { site, projectKey }: ProjectQuery,
  logger: Logger
): Promise<ProjectLookup> =>
  await withJira(site, logger, async (jira) => {
    const { style } = await fetchProject(jira, projectKey);
    const ids = await fetchProjectRoleIds(jira, projectKey);
    return {
      style: style === "classic" ? "company-managed" : "team-managed",
      roles: [...ids].map(([name, id]) => ({ id, name })),
    };
  });

export const siteRouter = (t: AnyConnectorTRPCInstance) =>
  t.router({
    get: withRouteLogging(t.procedure)
      .input(siteQuery.parse)
      .query(({ input, ctx }) => fetchSiteFacts(input, ctx.logger)),
  });

export const accountRouter = (t: AnyConnectorTRPCInstance) =>
  t.router({
    get: withRouteLogging(t.procedure)
      .input(accountQuery.parse)
      .query(({ input, ctx }) => fetchAccount(input, ctx.logger)),
  });

export const projectRouter = (t: AnyConnectorTRPCInstance) =>
  t.router({
    get: withRouteLogging(t.procedure)
      .input(projectQuery.parse)
      .query(({ input, ctx }) => fetchProjectFacts(input, ctx.logger)),
  });
