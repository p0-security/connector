import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";
import type { GaxiosResponse } from "googleapis-common";
import type { Mock } from "vitest";
import { describe, expect, it, vi } from "vitest";

import { createClients } from "../client.ts";
import { PolicyManager } from "../policy-manager.ts";
import type { AddMemberRequest, GcloudProjectResource } from "../types.ts";

vi.mock("../client");

describe("addMember", () => {
  it("adds a member to a policy which has no existing bindings", async () => {
    // Start with a blank policy
    const dummyPolicy: cloudresourcemanager_v3.Schema$Policy = {};

    // Dummy response from getIamPolicy which contains the dummy policy
    // @ts-expect-error partial stub
    const dummyResponse: GaxiosResponse<cloudresourcemanager_v3.Schema$Policy> =
      { data: dummyPolicy, status: 200, statusText: "OK" };

    (createClients as Mock).mockImplementation(() => {
      return {
        crm: {
          projects: {
            getIamPolicy: vi.fn().mockResolvedValue(dummyResponse),
            setIamPolicy: vi.fn().mockResolvedValue(dummyResponse),
          },
        },
      };
    });

    const client = await createClients();

    const dummyProjectResource: GcloudProjectResource = {
      type: "project",
      projectId: "p0-gcp-project",
    };

    const dummyCondition: cloudresourcemanager_v3.Schema$Expr = {
      title: "This is the title.",
      description: "This is the description.",
      expression: 'request.time < timestamp("<TIMESTAMP>")',
    };

    // Create a dummy request to add a member to the policy
    const dummyRequest: AddMemberRequest = {
      requestId: "request-id",
      projectId: "project-id",
      roleId: "role-id",
      member: "member-id",
      target: dummyProjectResource,
      condition: dummyCondition,
    };

    const policyManager = PolicyManager(client);
    await policyManager.addMember(dummyRequest);

    // The policy should now contain this new binding matching what was in the dummy request
    const expectedBinding: cloudresourcemanager_v3.Schema$Binding = {
      condition: dummyRequest.condition,
      members: [dummyRequest.member],
      role: dummyRequest.roleId,
    };

    const expectedPolicy: cloudresourcemanager_v3.Schema$Policy = {};
    expectedPolicy.version = 3;
    expectedPolicy.bindings = [expectedBinding];

    expect(client.crm.projects.getIamPolicy).toHaveBeenCalledTimes(1);
    expect(client.crm.projects.setIamPolicy).toHaveBeenCalledTimes(1);
    expect(client.crm.projects.setIamPolicy).toHaveBeenCalledWith({
      resource: `projects/${dummyProjectResource.projectId}`,
      requestBody: { policy: expectedPolicy },
    });
  });
});
