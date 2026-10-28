/** The project roles that an Atlas MCP configuration accepts, with their
 * labels in the Atlas UI. */
export const atlasProjectRoles = {
  GROUP_BACKUP_MANAGER: "Project Backup Manager",
  GROUP_CLUSTER_MANAGER: "Project Cluster Manager",
  GROUP_DATA_ACCESS_ADMIN: "Project Data Access Admin",
  GROUP_DATA_ACCESS_READ_ONLY: "Project Data Access Read Only",
  GROUP_DATA_ACCESS_READ_WRITE: "Project Data Access Read/Write",
  GROUP_DATABASE_ACCESS_ADMIN: "Project Database Access Admin",
  GROUP_OBSERVABILITY_VIEWER: "Project Observability Viewer",
  GROUP_OWNER: "Project Owner",
  GROUP_READ_ONLY: "Project Read Only",
  GROUP_SEARCH_INDEX_EDITOR: "Project Search Index Editor",
  GROUP_STREAM_PROCESSING_OWNER: "Project Stream Processing Owner",
} as const;

export type AtlasProjectRole = keyof typeof atlasProjectRoles;

export const atlasProjectRoleNames = Object.keys(atlasProjectRoles) as [
  AtlasProjectRole,
  ...AtlasProjectRole[],
];
