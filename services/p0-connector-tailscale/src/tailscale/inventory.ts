/**
 * What the connector reads out of a tailnet's policy file (as JSON).
 * Section names are matched without regard to case, because Tailscale
 * accepts `"Postures"` as well as `"postures"`.
 */

type Json = Record<string, unknown>;

/** Whether `value` is a JSON object (not an array or null). */
export const isObject = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The strings in `value`, when it is an array. */
export const strings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((each): each is string => typeof each === "string")
    : [];

/** The member named `name`, whatever its case: a section, or an entry's field. */
export const section = (policy: Json, name: string): unknown => {
  const wanted = name.toLowerCase();
  const key = Object.keys(policy).find((each) => each.toLowerCase() === wanted);
  return key === undefined ? undefined : policy[key];
};

/** The prefix of every posture P0 sets the attribute for. */
export const P0_POSTURE_PREFIX = "posture:p0_";

/** The prefix of every device attribute key P0 sets. */
export const P0_ATTRIBUTE_PREFIX = "custom:p0_";

export type Posture = { name: string; assertions: string[] };

/**
 * The postures defined in `postures`. A posture is either an array of
 * assertions (the legacy form) or `{ assertions, onFailure? }`, whose
 * field names match whatever their case; one file may hold both.
 */
export const posturesOf = (policy: Json): Posture[] => {
  const postures = section(policy, "postures");
  if (!isObject(postures)) return [];
  return Object.entries(postures).map(([name, value]) => ({
    name,
    assertions: isObject(value)
      ? strings(section(value, "assertions"))
      : strings(value),
  }));
};
