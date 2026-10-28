import { ProxyError, ValidationError } from "@p0security/sp-shared";

import {
  isAgenticIdentitySubject,
  parseWorkloadIdentityPrincipal,
} from "./agentic-identity/naming.ts";
import type { GcloudClients } from "./client.ts";
import { getOrgId, getOrgIdByProjectNumber } from "./helpers/ancestry.ts";
import logger from "./logger.ts";

const SERVICE_ACCOUNT_MEMBER_PREFIX = "serviceAccount:";
const WORKLOAD_IDENTITY_MEMBER_PREFIX = "principal://";

const allowedDomainsRegex = new RegExp(process.env.DOMAIN_ALLOW_PATTERN ?? "");

export const newMemberVerifier = (
  client: GcloudClients,
  metadata: {
    serviceAccountEmail: string;
    projectId: string;
  }
) => {
  const verifyUserOrGroup = (member: string) => {
    const [, ...email] = member.split(":");
    if (!allowedDomainsRegex.test(email.join())) {
      throw new ValidationError(
        `Domain verification failed for member ${member}.`
      );
    }
  };

  const verifyMember = async (member: string) => {
    if (member.startsWith(SERVICE_ACCOUNT_MEMBER_PREFIX)) {
      await verifyServiceAccount(member);
    } else if (member.startsWith(WORKLOAD_IDENTITY_MEMBER_PREFIX)) {
      await verifyWorkloadIdentityPrincipal(member);
    } else {
      verifyUserOrGroup(member);
    }
  };

  /** Federated principals, which reach here as the member of an agentic
   * identity's `roles/iam.workloadIdentityUser` binding.
   *
   * Validated **positively**: every path out of this function is either a
   * throw or a proof. Deliberately not routed through `verifyUserOrGroup` —
   * an unset `DOMAIN_ALLOW_PATTERN` compiles to the empty regex, which matches
   * everything, and the guard on the impersonation edge must not be able to
   * fail open. */
  const verifyWorkloadIdentityPrincipal = async (member: string) => {
    const principal = parseWorkloadIdentityPrincipal(member);
    if (!principal) {
      throw new ValidationError(
        `Member '${member}' is not a recognized workload identity principal.`
      );
    }
    if (!isAgenticIdentitySubject(principal.subject)) {
      throw new ValidationError(
        `Member '${member}' does not name an agentic identity subject.`
      );
    }
    // The pool must live in this perimeter's own organization. Without this,
    // a caller could bind impersonation of a service account in the customer's
    // project to a pool in someone else's project, and the subject shape alone
    // would not notice.
    const [orgId, poolOrgId] = await Promise.all([
      getOrgId(client, metadata.projectId),
      orgIdOfPoolProject(principal.poolProjectNumber),
    ]);
    if (!orgId || !poolOrgId || orgId !== poolOrgId) {
      throw new ValidationError(
        `Member '${member}' names a workload identity pool outside this organization.`
      );
    }
    logger.info(
      `Verified agentic identity principal in pool '${principal.poolId}'`
    );
  };

  const orgIdOfPoolProject = async (
    projectNumber: string
  ): Promise<string | undefined> => {
    try {
      return await getOrgIdByProjectNumber(client, projectNumber);
    } catch (error: any) {
      throw new ProxyError(
        "gcloud",
        `Error validating workload identity pool project '${projectNumber}'.`,
        error
      );
    }
  };

  const verifyServiceAccount = async (member: string) => {
    const serviceAccountEmail = member.slice(
      SERVICE_ACCOUNT_MEMBER_PREFIX.length
    );

    if (serviceAccountEmail === metadata.serviceAccountEmail) {
      throw new ValidationError(
        `Member '${member}' cannot be escalated through security perimeter.`
      );
    }

    const isValid = await isValidServiceAccount(serviceAccountEmail);

    if (!isValid) {
      throw new ValidationError(
        `Member '${member}' does not belong to a project under this account.`
      );
    }
  };

  const isValidServiceAccount = async (
    serviceAccountEmail: string
  ): Promise<boolean> => {
    try {
      const { projectId } = metadata;

      const [orgId, saProjectId] = await Promise.all([
        getOrgId(client, projectId),
        getServiceAccountProjectId(client, serviceAccountEmail),
      ]);

      if (!orgId || !saProjectId) {
        return false;
      }

      const saOrgId = await getOrgId(client, saProjectId);
      if (!saOrgId) {
        return false;
      }

      return orgId === saOrgId;
    } catch (error: any) {
      throw new ProxyError(
        "gcloud",
        `Error validating service account '${serviceAccountEmail}'.`,
        error
      );
    }
  };

  const getServiceAccountProjectId = async (
    client: GcloudClients,
    serviceAccountEmail: string
  ): Promise<string | undefined> => {
    const response = await client.iam.projects.serviceAccounts.get({
      name: `projects/-/serviceAccounts/${serviceAccountEmail}`,
    });

    const resourceName = response.data.name; // e.g., "projects/PROJECT_ID/serviceAccounts/service-account-email"
    const projectId = resourceName?.split("/")[1];

    logger.info(
      `Service account '${serviceAccountEmail}' belongs to project '${projectId}'.`
    );

    return projectId;
  };

  return {
    verifyMember,
  };
};
