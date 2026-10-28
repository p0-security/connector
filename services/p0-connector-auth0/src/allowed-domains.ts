const DOMAIN_ALLOW_PATTERN = "DOMAIN_ALLOW_PATTERN";

/**
 * The email domains the connector acts for, from
 * `DOMAIN_ALLOW_PATTERN` on the customer's own deployment.
 *
 * P0 can't grant anything to anyone whose Auth0 email is outside
 * them. A revoke isn't gated by them.
 */
export type AllowedDomains = {
  /** The pattern as deployed, for the install to display. */
  pattern: string;
  /** Whether the email's domain, the part after `@`, matches the pattern. */
  allows: (email: string) => boolean;
};

/**
 * Compiles the pattern, and throws when it's missing, blank or not a regular
 * expression. Unlike the GCP and Entra perimeters, there's no default.
 *
 * The pattern runs unanchored, so `acme\.com` also matches `notacme.com`.
 * Anchoring it is up to the customer: `^acme\.com$`.
 */
export const parseAllowedDomains = (
  raw: string | undefined
): AllowedDomains => {
  // A heredoc's trailing newline would compile, and then match no domain.
  const pattern = raw?.trim();
  if (!pattern) {
    throw new Error(
      `${DOMAIN_ALLOW_PATTERN} isn't set, or is blank. Set it to a regular expression that matches the email domains the connector may act for, such as ^example\\.com$.`
    );
  }
  let regex: RegExp;
  try {
    // The customer's own regex, from their own deployment.
    // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
    regex = new RegExp(pattern);
  } catch (error) {
    throw new Error(
      `${DOMAIN_ALLOW_PATTERN} isn't a valid regular expression: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error }
    );
  }
  return {
    pattern,
    allows: (email) => {
      const [, domain, ...rest] = email.split("@");
      // Without exactly one `@` there's no domain to test.
      if (!domain || rest.length > 0) return false;
      return regex.test(domain);
    },
  };
};

let parsed: AllowedDomains | undefined;

/**
 * The deployment's allowed domains, parsed once.
 *
 * Both entry points call this as they load, so a connector without a usable
 * pattern never starts.
 */
export const requireAllowedDomains = (): AllowedDomains =>
  (parsed ??= parseAllowedDomains(process.env[DOMAIN_ALLOW_PATTERN]));
