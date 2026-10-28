import { z } from "zod";

/**
 * A Google Cloud project id: 6 to 30 lowercase letters, digits and hyphens,
 * starting with a letter and not ending in a hyphen.
 */
export const projectId = z
  .string()
  .regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/, "must be a Google Cloud project id");

/**
 * A secret's bare name. The client would read a full resource name
 * (`projects/<project>/secrets/<name>`) as it stands, whatever `projectId`
 * says, so the schema refuses one.
 */
export const secretId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,255}$/, "must be a Secret Manager secret name");

/**
 * Where a secret lives in the customer's own secret manager. The beta runs on
 * Google Cloud only, so `manager` is always `gcp`.
 */
export const secretRef = z.object({
  manager: z.literal("gcp"),
  projectId,
  secretId,
});

export type SecretRef = z.infer<typeof secretRef>;

/** A P0 tenant's id, as P0 names an organization. */
export const tenantId = z
  .string()
  .regex(/^[A-Za-z0-9_-]{1,128}$/, "must be a P0 tenant id");

/**
 * A Jira Cloud site, and the admin service account's OAuth client the
 * connector calls it with. `cloudId` becomes a segment of every Jira call's
 * path, so it must be a UUID. `adminSecret` holds the admin client's secret,
 * as the secret's whole value. `tenantId` is the P0 organization the call is
 * for: only one may manage a site's P0 roles.
 */
export const site = z.object({
  cloudId: z.guid("must be an Atlassian cloud id"),
  adminClientId: z.string().min(1),
  adminSecret: secretRef,
  tenantId,
});

export type Site = z.infer<typeof site>;

/** A Jira project key, such as `ENG`. It becomes a path segment. */
export const projectKey = z
  .string()
  .regex(/^[A-Z][A-Z0-9_]+$/, "must be a Jira project key");

/**
 * An Atlassian account id, such as `5b10ac8d82e05b22cc7d4ef5` or
 * `712020:0e5a4f1e-…`. It is global across sites.
 */
export const accountId = z
  .string()
  .regex(/^[A-Za-z0-9:_-]{1,128}$/, "must be an Atlassian account id");

/** A project role's id, as Jira's role URLs end in it. */
export const roleId = z
  .string()
  .regex(/^\d+$/, "must be a Jira project role id");

/** `install.site.get`: what the site's admin account may do. */
export const siteQuery = z.object({ site });

export type SiteQuery = z.infer<typeof siteQuery>;

/**
 * `jiraAdmin` is whether the site's admin account holds the Administer Jira
 * global permission. P0 requires it at install. When it does, the lookup
 * fails with `validation_error` if another P0 organization manages the
 * site's P0 roles.
 */
export const siteLookup = z.object({ jiraAdmin: z.boolean() });

export type SiteLookup = z.infer<typeof siteLookup>;

/** `install.account.get`: the account behind an email on a site. */
export const accountQuery = z.object({ site, email: z.string().min(1) });

export type AccountQuery = z.infer<typeof accountQuery>;

export const accountLookup = z.object({ accountId });

export type AccountLookup = z.infer<typeof accountLookup>;

/** `install.project.get`: a project's style and its roles. */
export const projectQuery = z.object({ site, projectKey });

export type ProjectQuery = z.infer<typeof projectQuery>;

/** How a project manages access: Jira's `classic` is company-managed. */
export const projectStyle = z.enum(["company-managed", "team-managed"]);

export type ProjectStyle = z.infer<typeof projectStyle>;

/**
 * `roles` is every project role the project lists. P0 offers them as the
 * roles an agent can request in a team-managed project.
 */
export const projectLookup = z.object({
  style: projectStyle,
  roles: z.array(z.object({ id: roleId, name: z.string() })),
});

export type ProjectLookup = z.infer<typeof projectLookup>;
