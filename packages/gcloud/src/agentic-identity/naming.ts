/**
 * The shapes an agentic identity is allowed to take, in one place.
 *
 * Two strings carry this design: the service account P0 mints for each grant
 * in an agentic session, and the federated subject that is allowed to
 * impersonate it. Both
 * are chosen by P0's control plane and both are re-checked here, inside the
 * customer-hosted perimeter, because the perimeter does not trust the control
 * plane to have checked them (and a compromised control plane is exactly the
 * case the check exists for).
 *
 * Every pattern below is anchored, bounded in length and wildcard-free, and is
 * matched positively — never by an allow-pattern that defaults to permissive.
 */

/** Account id of a P0 agentic identity: `p0a-`, an adjective, an animal and
 * eight hex characters, e.g. `p0a-agile-otter-1f2e3d4c`.
 *
 * Random per grant, so no address is ever reused. Always matches Google's own
 * `[a-z][a-z0-9-]{4,28}[a-z0-9]`; the length cap is checked separately, in
 * {@link isAgenticIdentityAccountId}, because the words vary in length. The
 * `p0a-` prefix is what makes this an exact shape rather than a prefix test. */
export const AGENTIC_IDENTITY_ACCOUNT_ID = /^p0a-[a-z]+-[a-z]+-[0-9a-f]{8}$/;

/** Google's cap on a service-account id. */
const MAX_ACCOUNT_ID_LENGTH = 30;

/** The federated subject permitted to impersonate an agentic identity.
 *
 * Namespaced under `agentic-identity/` so it can never collide with a
 * gateway-derived `mcps/<backendId>/…` subject, and hashed so that a P0
 * session identifier never lands in a customer-readable IAM policy. */
export const AGENTIC_IDENTITY_SUBJECT = /^agentic-identity\/[0-9a-f]{16}$/;

/** A workload-identity-pool principal, as IAM writes it.
 *
 * Principal identifiers take the project *number*, not the project id — hence
 * `\d+` rather than a project-id pattern. */
export const WORKLOAD_IDENTITY_PRINCIPAL =
  /^principal:\/\/iam\.googleapis\.com\/projects\/(\d+)\/locations\/global\/workloadIdentityPools\/([a-zA-Z0-9-]+)\/subject\/(.+)$/;

export const SERVICE_ACCOUNT_DOMAIN_SUFFIX = ".iam.gserviceaccount.com";

/** GCP project ids: 6-30 characters, lowercase letter first. */
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

export type AgenticIdentityPrincipal = {
  /** The project **number** holding the workload identity pool. */
  poolProjectNumber: string;
  poolId: string;
  subject: string;
};

/** Parses a `principal://…` member into its parts, or returns undefined when
 * it is not a workload-identity principal at all. Shape alone — the pool's
 * provenance is checked by the caller, which has the clients to do it. */
export const parseWorkloadIdentityPrincipal = (
  member: string
): AgenticIdentityPrincipal | undefined => {
  const match = WORKLOAD_IDENTITY_PRINCIPAL.exec(member);
  if (!match) return undefined;
  const [, poolProjectNumber, poolId, subject] = match;
  return {
    poolProjectNumber: poolProjectNumber!,
    poolId: poolId!,
    subject: subject!,
  };
};

export const isAgenticIdentitySubject = (subject: string): boolean =>
  AGENTIC_IDENTITY_SUBJECT.test(subject);

export const isAgenticIdentityAccountId = (accountId: string): boolean =>
  accountId.length <= MAX_ACCOUNT_ID_LENGTH &&
  AGENTIC_IDENTITY_ACCOUNT_ID.test(accountId);

export const isProjectId = (projectId: string): boolean =>
  PROJECT_ID.test(projectId);

/** The one place an agentic identity's address is spelled.
 *
 * Google enforces the domain half of the shape; P0 enforces the rest. */
export const agenticIdentityEmail = (
  accountId: string,
  projectId: string
): string => `${accountId}@${projectId}${SERVICE_ACCOUNT_DOMAIN_SUFFIX}`;

/** Whether an address is one this perimeter may have minted, in the named
 * project. Anchored at both ends: a human's Workspace address can never match
 * it, which is the whole point. */
export const isAgenticIdentityEmail = (
  emailAddress: string,
  projectId: string
): boolean => {
  const [accountId, domain, ...rest] = emailAddress.split("@");
  if (rest.length > 0 || !accountId || !domain) return false;
  return (
    isAgenticIdentityAccountId(accountId) &&
    domain === `${projectId}${SERVICE_ACCOUNT_DOMAIN_SUFFIX}`
  );
};
