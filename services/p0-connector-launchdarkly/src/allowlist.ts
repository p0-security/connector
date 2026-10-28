import type { Logger } from "@p0security/connector-core";

import { refusal } from "./refusals.ts";

/**
 * The environment variable that holds the connector's own rule for who may
 * receive access: a regular expression for the allowed email domains. The
 * customer's Terraform sets it. P0 never sends it, so nothing in a call can
 * widen it.
 */
export const DOMAIN_ALLOW_PATTERN_ENV = "DOMAIN_ALLOW_PATTERN";

// A copy of the Harbor connector's rule (its src/allowlist.ts), under this
// connector's variable name, and with a `domain_not_allowed` message that
// doesn't quote the email.

/** Why there is no allowlist. `detail` is the regex engine's own message. */
type AllowlistProblem =
  { reason: "invalid_regex"; detail: string } | { reason: "unset" };

type Allowlist =
  | { ok: false; problem: AllowlistProblem }
  | { ok: true; pattern: string; regex: RegExp };

/**
 * `DOMAIN_ALLOW_PATTERN`, read now and compiled. `pattern` is the value less
 * the whitespace around it, which is what was compiled and what install
 * validation reports.
 *
 * The regex is anchored to the whole domain. The non-capturing group keeps
 * the anchors around an alternation: `a\.com|b\.com` must not become
 * `^a\.com` or `b\.com$`. DNS names are case-insensitive, so the regex is
 * too.
 */
export const compileAllowlist = (): Allowlist => {
  const pattern = process.env[DOMAIN_ALLOW_PATTERN_ENV]?.trim();
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
        detail: error instanceof Error ? error.message : String(error),
        reason: "invalid_regex",
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
 * What is wrong with the pattern, in a message's words: as part of a
 * sentence (`clause`), and as sentences of their own (`sentences`). Never the
 * pattern or the regex engine's message, which quotes it: a message reaches
 * requesters. The warning in the connector's own log has the engine's
 * message.
 */
export const ALLOWLIST_PROBLEMS: Record<
  AllowlistProblem["reason"],
  { clause: string; sentences: string }
> = {
  invalid_regex: {
    clause: `${DOMAIN_ALLOW_PATTERN_ENV} isn't a regular expression that compiles (the connector's log says why)`,
    sentences: `The connector's ${DOMAIN_ALLOW_PATTERN_ENV} isn't a regular expression that compiles. The connector's log says why.`,
  },
  unset: {
    clause: `${DOMAIN_ALLOW_PATTERN_ENV} isn't set`,
    sentences: `The connector's ${DOMAIN_ALLOW_PATTERN_ENV} isn't set.`,
  },
};

const renderProblem = ({ reason }: AllowlistProblem) =>
  ALLOWLIST_PROBLEMS[reason].clause;

/**
 * Refuses, with a `validation_error`, an email this connector may not look up
 * or give access to. Fails closed:
 *
 * - An unset, blank or invalid pattern refuses every email.
 * - An address that isn't exactly `<local>@<domain>` is refused, a quoted
 *   local part with an `@` in it included.
 * - The pattern must match the entire domain after the `@`, ignoring case, so
 *   `example\.com` rejects both `evil-example.com` and `sub.example.com`.
 *
 * The caller must check the exact string it then compares with what
 * LaunchDarkly holds. Trimming or otherwise normalising the email between
 * this check and that comparison would let through an address this check
 * never saw.
 *
 * The pattern is read on every call, before any call to LaunchDarkly. A
 * revoke never comes here: taking access away mustn't depend on the pattern
 * still admitting the member. Neither message nor log line repeats the
 * email.
 */
export const validateAllowedEmail = (email: string, logger: Logger): void => {
  const allowlist = compileAllowlist();
  if (!allowlist.ok) {
    // Every request fails until someone fixes the connector's setup, so the
    // customer's own logs say so.
    logger.warn(
      { problem: allowlist.problem },
      "the email domain allowlist is unusable, so every email is refused"
    );
    throw refusal({
      message: `The LaunchDarkly connector refuses every request: ${renderProblem(allowlist.problem)}. Set it on the connector to a regular expression for the email domains that may receive access.`,
      reason: "domain_pattern_unusable",
    });
  }
  if (!matches(allowlist, email)) {
    throw refusal({
      message:
        "The requester's email isn't in an email domain this LaunchDarkly connector allows. Ask your P0 admin which domains it allows.",
      reason: "domain_not_allowed",
    });
  }
};
