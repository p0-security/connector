import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";

import type { GcloudPolicyResources } from "./constants.ts";

export type AddMemberRequest = {
  requestId: string;
  projectId: string;
  roleId: string;
  member: string;
  target: GcloudPolicyResource | GcloudProjectResource;
  condition?: cloudresourcemanager_v3.Schema$Expr;
};
export type RemoveMemberRequest = AddMemberRequest;

export type RemoveMemberResponse = {
  isEmptyRole: boolean;
};

export type GcloudOrganizationResource = {
  type: "organization";
  organizationId: string;
};

export type GcloudProjectResource = {
  type: "project";
  projectId: string;
};

export type GcloudPolicyResourceWithProject = GcloudPolicyResource & {
  projectId: string;
};

/** @inline */
type GenericGcloudResource = Exclude<
  (typeof GcloudPolicyResources)[number],
  "instance" | "table" | "tunnelInstance"
>;

export type GcloudGenericResource = {
  fullResourceName?: string;
  type: GenericGcloudResource;
  name: string;
};

export type GcloudPolicyResource =
  | GcloudGenericResource
  | GcloudIapTunnelInstanceResource
  | GcloudInstanceResource
  | GcloudTableResource;

export type GcloudInstanceResource = {
  fullResourceName?: string;
  type: "instance";
  name: string;
  zoneName: string;
};

export type GcloudIapTunnelInstanceResource = {
  fullResourceName?: string;
  type: "tunnelInstance";
  name: string;
  zoneName: string;
};

export type GcloudTableResource = {
  fullResourceName?: string;
  type: "table";
  name: string;
  datasetName: string;
};

export type GcloudServiceMetadata = {
  serviceAccountEmail: string;
  projectId: string;
};
