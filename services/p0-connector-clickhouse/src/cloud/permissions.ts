/**
 * The permissions the API key's `p0-connector` custom role must hold, in the
 * order the install checks them. The installer lists them, and the app pins
 * its copy to this one.
 *
 * - `organization:view`: read the organization and its members.
 * - `organization:manage`: list, create, change and delete custom roles.
 * - `service:view`: read each service.
 * - `service:view-query-api-endpoints`: list P0's Query API endpoints.
 * - `service:manage-query-api-endpoints`: create, update and delete them.
 * - `organization:view-api-keys`: find the key's own UUID, which an
 *   endpoint's `apiKeyIds` takes, among the organization's keys.
 */
export const REQUIRED_PERMISSIONS = [
  "control-plane:organization:view",
  "control-plane:organization:manage",
  "control-plane:service:view",
  "control-plane:service:view-query-api-endpoints",
  "control-plane:service:manage-query-api-endpoints",
  "control-plane:organization:view-api-keys",
] as const;

export type RequiredPermission = (typeof REQUIRED_PERMISSIONS)[number];
