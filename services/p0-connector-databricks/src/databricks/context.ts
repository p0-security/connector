import { z } from "zod";

/**
 * The host of each Databricks account console, one per cloud Databricks runs
 * on, and the domain its workspaces are served from.
 *
 * The connector sends its AWS web identity token to `<accountsUrl>`, and that
 * token can be exchanged for the service principal's Databricks token. An
 * `accountsUrl` the control plane could point anywhere would hand that
 * credential to whoever runs the host, so only these exact hosts are accepted.
 * A workspace call carries the service principal's Databricks token, so for
 * the same reason a workspace URL must be a subdomain of one of these domains.
 */
export const DATABRICKS_HOSTS = {
  "accounts.cloud.databricks.com": "cloud.databricks.com", // AWS
  "accounts.cloud.databricks.us": "cloud.databricks.us", // AWS GovCloud
  "accounts.azuredatabricks.net": "azuredatabricks.net", // Azure
  "accounts.gcp.databricks.com": "gcp.databricks.com", // GCP
} as const;

const DATABRICKS_ACCOUNTS_HOSTS = Object.keys(DATABRICKS_HOSTS);
const DATABRICKS_WORKSPACE_DOMAINS = Object.values(DATABRICKS_HOSTS);

const isWorkspaceHost = (hostname: string) =>
  DATABRICKS_WORKSPACE_DOMAINS.some((domain) =>
    hostname.endsWith(`.${domain}`)
  );

const isAccountsHost = (hostname: string) =>
  DATABRICKS_ACCOUNTS_HOSTS.some((host) => host === hostname);

/**
 * Parses a bare `https://<host>` origin whose host passes `isAllowedHost`, and
 * normalizes it to `https://<host>` (no trailing slash). Paths, ports, query
 * strings and credentials are rejected rather than stripped, so a value that
 * isn't plainly a Databricks origin never reaches `fetch`.
 */
const databricksOrigin = (
  description: string,
  isAllowedHost: (hostname: string) => boolean
) =>
  z.url().transform((value, ctx) => {
    const url = new URL(value);
    const isBareOrigin =
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.port === "" &&
      (url.pathname === "" || url.pathname === "/") &&
      url.search === "" &&
      url.hash === "";
    if (!isBareOrigin || !isAllowedHost(url.hostname)) {
      ctx.addIssue({
        code: "custom",
        message: `${description} must be https://<host> on a Databricks domain`,
      });
      return z.NEVER;
    }
    return url.origin;
  });

/** The account console origin, e.g. `https://accounts.cloud.databricks.com`. */
export const accountsUrl = databricksOrigin(
  "Databricks accounts URL",
  isAccountsHost
);

/** A workspace origin, e.g. `https://dbc-1234abcd-5678.cloud.databricks.com`. */
export const workspaceUrl = databricksOrigin(
  "Databricks workspace URL",
  isWorkspaceHost
);

/**
 * A numeric Databricks ID, such as a workspace ID or an account SCIM user ID,
 * as a string of digits. These go into URL paths, so anything else is refused
 * before a call is made.
 */
export const databricksId = z
  .string()
  .regex(/^\d+$/, "must be a numeric Databricks ID");

/**
 * Which Databricks account the connector acts in, and as which of its service
 * principals. Every access type's `RequestContext` extends this, and the
 * Databricks client authenticates from it alone.
 */
export const accountContext = z.object({
  requestId: z.string().min(1),
  accountsUrl,
  /** The Databricks account ID. */
  accountId: z.guid(),
  /** The connector service principal's `application_id` in that account. */
  applicationId: z.guid(),
});

export type DatabricksAccountContext = z.infer<typeof accountContext>;

/**
 * Identifies the account and service principal a context authenticates as.
 * The token cache is keyed on it, and so is anything else cached per
 * principal. It lives here, not beside the token cache, so the schemas that
 * key a cache on it don't load the STS client.
 */
export const cacheKey = ({
  accountsUrl,
  accountId,
  applicationId,
}: DatabricksAccountContext) => `${accountsUrl}|${accountId}|${applicationId}`;
