/**
 * Project → organization resolution, shared by every guard that answers "is
 * this thing inside the organization this perimeter serves?".
 */
import { ProxyError } from "@p0security/sp-shared";
import axios from "axios";

import type { GcloudClients } from "../client.ts";
import logger from "../logger.ts";

const getAncestors = async (client: GcloudClients, projectId: string) => {
  const ancestryUrl = `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getAncestry`;
  const accessToken = await client.auth.getAccessToken();

  const token =
    typeof accessToken === "string" ? accessToken : accessToken?.token;
  if (!token) {
    throw new ProxyError(
      "gcloud",
      "Failed to fetch access token.",
      new Error("Failed to fetch access token")
    );
  }
  const ancestryResponse = await axios.post(
    ancestryUrl,
    {},
    { headers: { Authorization: `Bearer ${token}` } }
  );

  return ancestryResponse.data.ancestor || [];
};

export const getOrgId = async (
  client: GcloudClients,
  projectId: string
): Promise<string | undefined> => {
  const ancestors = await getAncestors(client, projectId);
  for (const ancestor of ancestors) {
    if (ancestor.resourceId?.type === "organization") {
      const orgId = ancestor.resourceId.id;
      logger.info(`Project '${projectId}' belongs to org '${orgId}'`);
      return orgId;
    }
  }

  logger.info(`Project '${projectId}' does not belong to an organization.`);
  return undefined;
};

/** The organization of the project holding a workload identity pool.
 *
 * Principal identifiers carry the project **number**; `getAncestry` takes a
 * project id, so the two are bridged through a Resource Manager read that
 * accepts either. */
export const getOrgIdByProjectNumber = async (
  client: GcloudClients,
  projectNumber: string
): Promise<string | undefined> => {
  const { data } = await client.crm.projects.get({
    name: `projects/${projectNumber}`,
  });
  const projectId = data.projectId;
  if (!projectId) return undefined;
  return await getOrgId(client, projectId);
};
