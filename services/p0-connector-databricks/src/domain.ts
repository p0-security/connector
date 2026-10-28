import { ConnectorError, createLogger } from "@p0security/connector-core";
import { z } from "zod";

const logger = createLogger();

/**
 * The Lambda environment variable holding `domainPattern`, the regex of email
 * domains P0 may grant to. The customer's install terraform sets it; P0's
 * control plane can't.
 */
export const DOMAIN_PATTERN_ENV = "DOMAIN_PATTERN";

/**
 * `DOMAIN_PATTERN`, compiled. It must be set to a valid regex, and the regex
 * is anchored to the whole domain. The non-capturing group keeps the anchors
 * around an alternation: `a\.com|b\.com` must not become `^a\.com` or
 * `b\.com$`. DNS names are case-insensitive, so the regex is too.
 */
const domainPattern = z
  .string({ error: `${DOMAIN_PATTERN_ENV} is not set` })
  .trim()
  .min(1, `${DOMAIN_PATTERN_ENV} is not set`)
  .transform((pattern, ctx) => {
    try {
      return new RegExp(`^(?:${pattern})$`, "i");
    } catch {
      ctx.addIssue({
        code: "custom",
        message: `${DOMAIN_PATTERN_ENV} is not a valid regex`,
      });
      return z.NEVER;
    }
  });

type DomainPattern =
  { ok: false; problem: string } | { ok: true; regex: RegExp };

const readDomainPattern = (): DomainPattern => {
  const parsed = domainPattern.safeParse(process.env[DOMAIN_PATTERN_ENV]);
  return parsed.success
    ? { ok: true, regex: parsed.data }
    : { ok: false, problem: parsed.error.issues[0]?.message ?? "invalid" };
};

/** The domain after the `@` of an address that is exactly `<local>@<domain>`. */
const domainOf = (email: string) => {
  const parts = email.split("@");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return undefined;
  return parts[1];
};

const matches = (pattern: DomainPattern, email: string) => {
  const domain = domainOf(email);
  return pattern.ok && domain !== undefined && pattern.regex.test(domain);
};

/**
 * Whether `email`'s domain matches `DOMAIN_PATTERN`, anchored to the whole
 * domain after the `@`, ignoring case. Fails closed:
 *
 * - an unset, empty or invalid pattern refuses every user;
 * - an address that isn't exactly `<local>@<domain>` is refused;
 * - the pattern must match the entire domain, so `example\.com` rejects both
 *   `evil-example.com` and `sub.example.com`. To allow subdomains, the pattern
 *   has to say so, e.g. `(.+\.)?example\.com`.
 *
 * This deliberately doesn't follow the Entra perimeter's or
 * `packages/gcloud`'s domain checks, which are unanchored and allow everyone
 * when their variable is unset.
 */
export const emailDomainIsAllowed = (email: string): boolean =>
  matches(readDomainPattern(), email);

/**
 * Refuses, with a `validation_error` that says how to fix it, unless
 * `DOMAIN_PATTERN` is set to a valid regex. Install validation calls this, so
 * a missing pattern shows up at install rather than on the first request.
 */
export const assertDomainPatternIsValid = (requestId: string) => {
  const pattern = readDomainPattern();
  if (!pattern.ok) {
    logger.error(
      { requestId, problem: pattern.problem },
      "domain verification is not configured; refusing every user"
    );
    throw new ConnectorError({
      type: "validation_error",
      message: `Domain verification is not configured: ${pattern.problem}. Set ${DOMAIN_PATTERN_ENV} on the connector to a regex of the email domains P0 may grant to.`,
      payload: { requestId },
    });
  }
};

/**
 * Domain verification for one user, by their Databricks `userName` (see
 * {@link emailDomainIsAllowed}). The rule is the `userName` only. A user's
 * `emails` can be edited by an IdP or an admin, so they never widen the check.
 * A customer whose users' `userName` is on another domain (an Azure UPN, say)
 * adds that domain to the pattern.
 *
 * It gates every lookup that resolves a user from an email, and every grant:
 * a user who fails is refused with a `validation_error` that says why, instead
 * of the framework's bare "is not namespaced".
 *
 * A revoke passes `alreadyGranted`, and is never refused. P0 recorded the
 * user's identity at stage, after they passed, and a revoke must never depend
 * on the pattern still admitting them: narrowing `DOMAIN_PATTERN` (or leaving
 * it unset) would leave the access in place. So this logs a warning instead,
 * which the customer can see, and returns whether the user still passes. A
 * caller that gets `false` must only remove access, never add it.
 */
export const verifyEmailDomain = ({
  email,
  requestId,
  alreadyGranted,
}: {
  /** A Databricks `userName`, or the requestor's email before a user is found. */
  email: string;
  requestId: string;
  /** Whether the call only removes access P0 already granted. */
  alreadyGranted: boolean;
}): boolean => {
  const pattern = readDomainPattern();
  if (matches(pattern, email)) return true;
  if (!alreadyGranted) {
    assertDomainPatternIsValid(requestId);
    throw new ConnectorError({
      type: "validation_error",
      message: `Domain verification refused ${email}: ${DOMAIN_PATTERN_ENV} on the connector must match the whole domain after the @.`,
      payload: { requestId, query: email },
    });
  }
  logger.warn(
    {
      requestId,
      query: email,
      ...(pattern.ok ? {} : { problem: pattern.problem }),
    },
    pattern.ok
      ? `${email} no longer passes domain verification (${DOMAIN_PATTERN_ENV}); P0 will only remove the access it already granted`
      : "domain verification is not configured; P0 will only remove the access it already granted"
  );
  return false;
};
