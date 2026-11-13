import { ConnectorError } from "@p0security/connector-core";

const REGEX_SPECIALS = /[\\^$.|?*+()[\]{}/-]/g;

/** Escapes a literal for a regular expression, `/` included so it also fits
 * a Logs Insights `/…/` regex literal. */
export const escapeRegex = (value: string) =>
  value.replace(REGEX_SPECIALS, "\\$&");

/**
 * The regular expression source for an IAM-style pattern: `*` is any run of
 * characters, `?` any one character, and everything else is literal.
 * `wildcard` replaces `*`, for a segment that mustn't cross a `/`.
 */
export const globSource = (pattern: string, wildcard = ".*") =>
  pattern
    .split("")
    .map((c) => (c === "*" ? wildcard : c === "?" ? "." : escapeRegex(c)))
    .join("");

export const globToRegExp = (pattern: string, flags = "") =>
  new RegExp(`^${globSource(pattern)}$`, flags);

/** Whether `value` matches at least one pattern. */
export const matchesAnyGlob = (
  value: string,
  patterns: readonly string[],
  flags = ""
) => patterns.some((p) => globToRegExp(p, flags).test(value));

// Logs Insights literals can't hold a line break; nothing P0 sends has one.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/** Rejects a value that can't be placed in a Logs Insights query. */
export const assertQuerySafe = (value: string) => {
  if (CONTROL_CHARACTERS.test(value)) {
    throw new ConnectorError({
      type: "validation_error",
      message: "A query value holds a control character",
      payload: {},
    });
  }
  return value;
};

/** A Logs Insights string literal. */
export const insightsString = (value: string) =>
  `"${assertQuerySafe(value).replace(/["\\]/g, "\\$&")}"`;
