/**
 * The scopes the Tailscale credential must hold. Install validation probes
 * each one and names any that's missing.
 */
export const REQUIRED_SCOPES: readonly string[] = [
  "policy_file:read",
  "users:read",
  "devices:core:read",
  "devices:posture_attributes",
  "devices:routes:read",
  "services:read",
];

/**
 * Whether `held` covers `needed`: a write scope covers its `:read`, `all`
 * covers every scope, and `all:read` every `:read` one.
 */
export const covers = (held: readonly string[], needed: string): boolean =>
  held.includes(needed) ||
  held.includes("all") ||
  (needed.endsWith(":read") &&
    (held.includes("all:read") || held.includes(needed.slice(0, -5))));

/**
 * Scopes the credential must not hold: each can write the policy file,
 * which P0 never does. `all` includes `policy_file`.
 */
export const REFUSED_SCOPES: readonly string[] = ["policy_file", "all"];

/**
 * What the read-only token asks for: discovery, checks and listings. Each
 * is held by the credential, or implied by a write scope it holds.
 */
export const READ_SCOPES: readonly string[] = [
  "users:read",
  "devices:core:read",
  "devices:routes:read",
  "services:read",
  "policy_file:read",
  "devices:posture_attributes:read",
];

/**
 * What a grant or revoke's token asks for. It never holds `policy_file`
 * write, so no call can write the policy file.
 */
export const WRITE_SCOPES: readonly string[] = ["devices:posture_attributes"];
