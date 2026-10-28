/**
 * The Management API scopes the connector's client must be granted, and what
 * each is for. Install validation fails listing any that the client's token
 * doesn't carry. Scopes beyond these are ignored.
 */
export const REQUIRED_SCOPES = [
  // `GET /users-by-email`, and the reads of a user's roles and permissions.
  "read:users",
  // `GET /roles`, and a user's roles.
  "read:roles",
  "read:role_members",
  // `POST` and `DELETE /users/{id}/roles` and `/users/{id}/permissions`.
  "update:users",
  "create:role_members",
  "delete:role_members",
  // `GET /resource-servers`: the APIs and their permissions.
  "read:resource_servers",
  // `GET /users/{id}/effective-permissions`: which permissions are direct.
  "read:user_effective_permissions",
  // Organizations, their members and the members' roles.
  "read:organizations",
  "read:organization_members",
  "read:organization_member_roles",
  "create:organization_members",
  "delete:organization_members",
  "create:organization_member_roles",
  "delete:organization_member_roles",
] as const;

export type RequiredScope = (typeof REQUIRED_SCOPES)[number];

/** The required scopes `granted` lacks, in {@link REQUIRED_SCOPES}' order. */
export const missingScopes = (granted: readonly string[]): RequiredScope[] => {
  const held = new Set(granted);
  return REQUIRED_SCOPES.filter((scope) => !held.has(scope));
};
