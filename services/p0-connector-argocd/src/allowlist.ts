// copy of services/p0-connector-harbor/src/allowlist.ts, for Argo CD
import type { Logger } from "@p0security/connector-core";

import { refusal } from "./refusals.ts";

/**
 * The environment variable that holds the connector's own rule for who may
 * receive access: a regular expression for the allowed email domains. The
 * customer's Terraform sets it. P0 never sends it, so nothing in a call can
 * widen it.
 */
export const ALLOWED_EMAIL_DOMAIN_PATTERN_ENV = "ALLOWED_EMAIL_DOMAIN_PATTERN";

// Harbor's rule word for word but for the connector's name, itself a copy of
// services/p0-connector-databricks/src/domain.ts.
// TODO(INT-418): merge the copies into one rule in @p0security/connector.

/** Why there is no allowlist. `detail` is the regex engine's own message. */
type AllowlistProblem =
  { reason: "invalid_regex"; detail: string } | { reason: "unset" };

type Allowlist =
  | { ok: false; problem: AllowlistProblem }
  | { ok: true; pattern: string; regex: RegExp };

/**
 * `ALLOWED_EMAIL_DOMAIN_PATTERN`, read now and compiled. `pattern` is the
 * value less the whitespace around it, which is what was compiled and what
 * install validation reports.
 *
 * The regex is anchored to the whole domain. The non-capturing group keeps
 * the anchors around an alternation: `a\.com|b\.com` must not become
 * `^a\.com` or `b\.com$`. DNS names are case-insensitive, so the regex is
 * too.
 */
export const compileAllowlist = (): Allowlist => {
  const pattern = process.env[ALLOWED_EMAIL_DOMAIN_PATTERN_ENV]?.trim();
  if (!pattern) return { ok: false, problem: { reason: "unset" } };
  try {
    // On its own first. Wrapped, `a\.com)|(.*` compiles to
    // `^(?:a\.com)|(.*)$`, which allows any domain.
    new RegExp(pattern);
    return { ok: true, pattern, regex: new RegExp(`^(?:${pattern})$`, "i") };
  } catch (error) {
    return {
      ok: false,
      problem: {
        reason: "invalid_regex",
        detail: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

/** The domain after the `@` of an address that is exactly `<local>@<domain>`. */
const domainOf = (email: string) => {
  const parts = email.split("@");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return undefined;
  return parts[1];
};

const matches = (allowlist: Allowlist, email: string) => {
  const domain = domainOf(email);
  return allowlist.ok && domain !== undefined && allowlist.regex.test(domain);
};

/**
 * What is wrong with the pattern, for a message. Never the pattern or the
 * regex engine's message, which quotes it: a message reaches requesters. The
 * warning in the connector's own log has the engine's message.
 */
const describeProblem = (problem: AllowlistProblem) =>
  problem.reason === "unset"
    ? `${ALLOWED_EMAIL_DOMAIN_PATTERN_ENV} isn't set`
    : `${ALLOWED_EMAIL_DOMAIN_PATTERN_ENV} isn't a regular expression that compiles (the connector's log says why)`;

/**
 * Refuses, with a `validation_error`, an email this connector may not look up
 * or give access to. Fails closed:
 *
 * - an unset, blank or invalid pattern refuses every email;
 * - an address that isn't exactly `<local>@<domain>` is refused, a quoted
 *   local part with an `@` in it included;
 * - the pattern must match the entire domain after the `@`, ignoring case, so
 *   `example\.com` rejects both `evil-example.com` and `sub.example.com`.
 *
 * The caller must check the exact string it then writes a policy line for.
 * Trimming or otherwise normalising the email between this check and the
 * line would let through an address this check never saw. (The line lowers
 * its case, which the check ignores.)
 *
 * The pattern is read on every call, before any call to Argo CD. A revoke
 * never comes here: taking access away mustn't depend on the pattern still
 * admitting the user.
 */
export const assertAllowedEmail = (email: string, logger: Logger): void => {
  const allowlist = compileAllowlist();
  if (!allowlist.ok) {
    // Every request fails until someone fixes the connector's setup, so the
    // customer's own logs say so. The email isn't at fault, so neither the
    // line nor the message repeats it.
    logger.warn(
      { problem: allowlist.problem },
      "the email domain allowlist is unusable; refusing every email"
    );
    throw refusal({
      reason: "domain_pattern_unusable",
      message: `The Argo CD connector refuses every request: ${describeProblem(allowlist.problem)}. Set it on the connector to a regular expression for the email domains that may receive access.`,
    });
  }
  if (!matches(allowlist, email)) {
    throw refusal({
      reason: "domain_not_allowed",
      message: `${email} isn't in an email domain this Argo CD connector allows.`,
    });
  }
};
