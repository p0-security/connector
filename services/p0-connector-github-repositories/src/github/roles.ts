/** GitHub's built-in repository roles, keyed by the value PUT accepts, with the names GitHub shows. Lowest first. */
export const BUILT_IN_ROLES = [
  { key: "pull", value: "Read" },
  { key: "triage", value: "Triage" },
  { key: "triage_plus", value: "Triage Plus" },
  { key: "push", value: "Write" },
  { key: "maintain", value: "Maintain" },
  { key: "admin", value: "Admin" },
] as const;

// GitHub names two built-ins differently depending on where you look: the
// GraphQL `roleName` and the UI say read and write, where PUT takes pull and push.
const PUT_ALIASES: Partial<Record<string, string>> = {
  read: "pull",
  write: "push",
};

// Lowercased, with spaces and hyphens as underscores, so a display name
// ("Triage Plus") and a PUT value ("triage_plus") meet in the middle.
const normalize = (role: string) => role.toLowerCase().replace(/[\s-]+/g, "_");

const builtInRole = (role: string) => {
  const name = normalize(role);
  const key = PUT_ALIASES[name] ?? name;
  return BUILT_IN_ROLES.find(
    (builtIn) => builtIn.key === key || normalize(builtIn.value) === name
  );
};

/**
 * A role in the form PUT accepts.
 *
 * A built-in role is matched on its PUT value or the name GitHub shows,
 * ignoring case and spacing, and de-aliased (`Write` becomes `push`,
 * `Triage Plus` becomes `triage_plus`). A custom role keeps the name GitHub
 * gave it, since that name is what PUT takes.
 */
export const toPutRole = (role: string): string =>
  builtInRole(role)?.key ?? role;

/** The name GitHub shows for a role, for messages a person reads. */
export const displayRole = (role: string): string =>
  builtInRole(role)?.value ?? role;
