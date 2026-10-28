import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";

import type { GcloudClients } from "./client.ts";
import logger from "./logger.ts";
import {
  conditionalIAMSupported,
  datasetAclToIamPolicy,
  iamPolicyToDatasetAcl,
  toCrmPolicy,
  toStoragePolicy,
} from "./resource.ts";
import type {
  GcloudOrganizationResource,
  GcloudPolicyResource,
  GcloudPolicyResourceWithProject,
  GcloudProjectResource,
} from "./types.ts";

export const PolicyRouter = (client: GcloudClients) => {
  /** Get this project's IAM policy from GCP */
  // cf. https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy
  // we request version 3 because that includes policy conditions,
  // see https://cloud.google.com/iam/docs/policies#specifying-version-get
  const getPolicy = async (
    targetResource:
      | GcloudOrganizationResource
      | GcloudPolicyResourceWithProject
      | GcloudProjectResource
  ): Promise<cloudresourcemanager_v3.Schema$Policy> => {
    if (targetResource.type === "organization") {
      const response = await client.crm.organizations.getIamPolicy({
        resource: `organizations/${targetResource.organizationId}`,
        requestBody: {
          options: {
            requestedPolicyVersion: 3,
          },
        },
      });
      return response.data;
    } else if (targetResource.type === "project") {
      const response = await client.crm.projects.getIamPolicy({
        resource: `projects/${targetResource.projectId}`,
        requestBody: {
          options: {
            requestedPolicyVersion: 3,
          },
        },
      });
      return response.data;
    } else {
      return getPolicyResource(targetResource.projectId, targetResource);
    }
  };

  /** Sets this project's IAM policy in GCP */
  // NOTE: This assumes that the policy hasn't been modified since the last getPolicy() call
  // If this happens, CRM should reject this update due to a stale etag.
  // cf. https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy
  const setPolicy = async (
    projectId: string,
    policy: cloudresourcemanager_v3.Schema$Policy,
    target: GcloudPolicyResource | GcloudProjectResource
  ) => {
    // Using conditions requires policy version 3
    // see https://cloud.google.com/iam/help/allow-policies/versions
    policy.version =
      target.type === "project" || conditionalIAMSupported(target) ? 3 : 1;
    try {
      if (target.type === "project") {
        const response = await client.crm.projects.setIamPolicy({
          resource: `projects/${target.projectId}`,
          requestBody: { policy },
        });
        return response.data;
      } else {
        return setPolicyResource(projectId, target, policy);
      }
    } catch (e) {
      logger.error({ err: e }, "Error setting project IAM policy");
      throw e;
    }
  };

  const getPolicyResource = async (
    projectId: string,
    targetResource: GcloudPolicyResource
  ): Promise<cloudresourcemanager_v3.Schema$Policy> => {
    const resource = formatPolicyResourceName(projectId, targetResource);
    const policyVersion = conditionalIAMSupported(targetResource) ? 3 : 1;
    switch (targetResource.type) {
      case "serviceaccount":
        return (
          await client.iam.projects.serviceAccounts.getIamPolicy({
            resource,
            "options.requestedPolicyVersion": policyVersion,
          })
        ).data;
      case "instance":
        return (
          await client.compute.instances.getIamPolicy({
            resource,
            optionsRequestedPolicyVersion: policyVersion,
            zone: targetResource.zoneName,
            project: projectId,
          })
        ).data;
      case "tunnelInstance":
        return (
          await client.iap.v1.getIamPolicy({
            resource,
          })
        ).data;
      case "bucket":
        return toCrmPolicy(
          (
            await client.storage.buckets.getIamPolicy({
              bucket: resource,
              optionsRequestedPolicyVersion: policyVersion,
            })
          ).data
        );
      case "table":
        return (
          await client.bq.tables.getIamPolicy({
            resource,
            requestBody: {
              options: { requestedPolicyVersion: policyVersion },
            },
          })
        ).data;
      case "dataset":
        return datasetAclToIamPolicy(
          (
            await client.bq.datasets.get({
              datasetId: resource,
              projectId,
            })
          ).data.access ?? []
        );
      case "secret":
        return (
          await client.secretManager.projects.secrets.getIamPolicy({
            resource,
            "options.requestedPolicyVersion": policyVersion,
          })
        ).data;
      default:
        throw assertNever(
          "Unexpected code state: unknown target resource type"
        );
    }
  };

  const setPolicyResource = async (
    projectId: string,
    targetResource: GcloudPolicyResource,
    policy: cloudresourcemanager_v3.Schema$Policy
  ): Promise<void> => {
    const resource = formatPolicyResourceName(projectId, targetResource);
    switch (targetResource.type) {
      case "serviceaccount":
        await client.iam.projects.serviceAccounts.setIamPolicy({
          resource,
          requestBody: { policy },
        });
        return;
      case "instance":
        await client.compute.instances.setIamPolicy({
          resource,
          zone: targetResource.zoneName,
          project: projectId,
          requestBody: { policy },
        });
        return;
      case "tunnelInstance":
        await client.iap.v1.setIamPolicy({
          resource,
          requestBody: { policy },
        });
        return;
      case "bucket":
        await client.storage.buckets.setIamPolicy({
          bucket: resource,
          requestBody: toStoragePolicy(policy),
        });
        return;
      case "table":
        await client.bq.tables.setIamPolicy({
          resource,
          requestBody: { policy },
        });
        return;
      case "dataset":
        await client.bq.datasets.patch({
          datasetId: resource,
          projectId,
          requestBody: {
            access: iamPolicyToDatasetAcl(policy),
          },
        });
        return;
      case "secret":
        await client.secretManager.projects.secrets.setIamPolicy({
          resource,
          requestBody: { policy },
        });
        return;
      default:
        throw assertNever(
          "Unexpected code state: unknown target resource type"
        );
    }
  };

  const formatPolicyResourceName = (
    projectId: string,
    resource: GcloudPolicyResource
  ) => {
    switch (resource.type) {
      case "serviceaccount":
        return `projects/${projectId}/serviceAccounts/${resource.name}`;
      case "instance":
        return resource.name;
      case "tunnelInstance":
        return `projects/${projectId}/iap_tunnel/zones/${resource.zoneName}/instances/${resource.name}`;
      case "bucket":
        return resource.name;
      case "dataset":
        return resource.name;
      case "table":
        return `projects/${projectId}/datasets/${resource.datasetName}/tables/${resource.name}`;
      case "secret":
        return `projects/${projectId}/secrets/${resource.name}`;
      default:
        throw assertNever("Unexpected code state: unknown resource type");
    }
  };

  const assertNever = (message: string) => {
    logger.error({}, message);
    return new Error(message);
  };

  return {
    getPolicy,
    setPolicy,
  };
};
