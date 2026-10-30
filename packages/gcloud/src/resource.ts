import type { bigquery_v2 } from "@googleapis/bigquery";
import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";
import type { storage_v1 } from "@googleapis/storage";
import { groupBy, map } from "lodash-es";

import { GcloudConditionalIamSupportedResources } from "./constants.ts";
import type { GcloudPolicyResource } from "./types.ts";

export const conditionalIAMSupported = (resource: GcloudPolicyResource) =>
  isa(GcloudConditionalIamSupportedResources, resource.type);

const isa = <T>(allowed: readonly T[], value: any): value is T =>
  (allowed as any[]).includes(value);

export const toCrmPolicy = (
  policy: storage_v1.Schema$Policy
): cloudresourcemanager_v3.Schema$Policy => ({
  bindings: policy.bindings as cloudresourcemanager_v3.Schema$Binding[],
  etag: policy.etag,
  version: policy.version,
});
type DatasetAccess = {
  dataset?: bigquery_v2.Schema$DatasetAccessEntry;
  domain?: string;
  groupByEmail?: string;
  iamMember?: string;
  role?: string;
  routine?: bigquery_v2.Schema$RoutineReference;
  specialGroup?: string;
  userByEmail?: string;
  view?: bigquery_v2.Schema$TableReference;
};

const datasetPrincipalToIamMember = (access: DatasetAccess): string => {
  // we will only grant access to users, groups, or service accounts (which falls under 'iamMember')
  // but we still need to encode the rest because we must pass in the full ACL to the datasets patch method
  // just encode with fieldName:jsonValue
  if (access.dataset) return `dataset:${JSON.stringify(access.dataset)}`;
  if (access.domain) return `domain:${access.domain}`;
  if (access.groupByEmail) return `group:${access.groupByEmail}`;
  if (access.userByEmail) return `user:${access.userByEmail}`;
  if (access.specialGroup) return `specialGroup:${access.specialGroup}`;
  if (access.routine) return `routine:${JSON.stringify(access.routine)}`;
  if (access.view) return `view:${JSON.stringify(access.view)}`;
  return access.iamMember ?? "";
};

export const datasetAclToIamPolicy = (
  acl: DatasetAccess[]
): cloudresourcemanager_v3.Schema$Policy => {
  const bindings = map(groupBy(acl, "role"), (datasetPrincipals, role) => ({
    role,
    members: datasetPrincipals.map(datasetPrincipalToIamMember),
  }));
  return { bindings };
};

const iamToDatasetAccess = (
  member: string,
  role: string | undefined
): DatasetAccess => {
  const [memberType, ...rest] = member.split(":");
  const memberName = rest.join(":");
  // Authorized datasets, views, and routines will not have a "role"
  switch (memberType) {
    case "user":
      return { userByEmail: memberName, role };
    case "group":
      return { groupByEmail: memberName, role };
    case "domain":
      return { domain: memberName, role };
    case "specialGroup":
      return { specialGroup: memberName, role };
    case "dataset": {
      const val = JSON.parse(memberName);
      return { dataset: val };
    }
    case "view": {
      const val = JSON.parse(memberName);
      return { view: val };
    }
    case "routine": {
      const val = JSON.parse(memberName);
      return { routine: val };
    }
    default:
      // preserve the full member string (e.g. `principal://...`, `serviceAccount:...`) —
      // memberName would drop everything up to and including the first colon
      return { iamMember: member, role };
  }
};

export const iamPolicyToDatasetAcl = (
  policy: cloudresourcemanager_v3.Schema$Policy
): DatasetAccess[] => {
  const acl: DatasetAccess[] = [];

  for (const binding of policy.bindings ?? []) {
    for (const member of binding.members ?? []) {
      const access = iamToDatasetAccess(member, binding.role ?? undefined);
      acl.push(access);
    }
  }
  return acl;
};

export const toStoragePolicy = (
  policy: cloudresourcemanager_v3.Schema$Policy
): storage_v1.Schema$Policy => ({
  bindings: policy.bindings as Array<{
    condition?: cloudresourcemanager_v3.Schema$Expr;
    members?: string[];
    role?: string;
  }>,
  etag: policy.etag,
  version: policy.version,
});
