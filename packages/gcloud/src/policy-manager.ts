import type { cloudresourcemanager_v3 } from "@googleapis/cloudresourcemanager";
import type { iam_v1 } from "@googleapis/iam";

import type { GcloudClients } from "./client.ts";
import logger from "./logger.ts";
import { PolicyRouter } from "./policy-router.ts";
import { celEqual } from "./resource.ts";
import type { AddMemberRequest, RemoveMemberRequest } from "./types.ts";

export function PolicyManager(client: GcloudClients) {
  const policyRouter = PolicyRouter(client);

  const addMember = async (request: AddMemberRequest) => {
    const policy = await policyRouter.getPolicy({
      ...request.target,
      projectId: request.projectId,
    });

    const bindingList = policy.bindings ?? [];
    const binding = bindingList.find((b) => {
      if (!b.condition?.expression && !request.condition) {
        // if neither the binding nor request has a condition, check that roles are equal
        return b.role === request.roleId;
      }

      return (
        // otherwise, check that roles are equal, both conditions exist, and are equal
        b.role === request.roleId &&
        b.condition?.title === request.condition?.title &&
        b.condition?.expression &&
        request.condition?.expression &&
        celEqual(b.condition.expression, request.condition.expression)
      );
    });

    // Three possibilities:
    // 1. Binding exists, includes member already (skip operation)
    // 2. Binding exists, does not include member (add member)
    // 3. Binding doesn't exist (make it)

    const memberList = binding?.members ?? [];
    if (binding && memberList.includes(request.member)) {
      logger.info(
        { request },
        "Principal already has role; skipping member addition"
      );
      return;
    }

    if (binding) {
      logger.info({ request }, "Adding member to existing binding");
      memberList.push(request.member);
      binding.members = memberList;
    } else {
      logger.info({ request }, "Creating new binding and adding member");

      // TODO: Set expiry as policy condition
      const newBinding: cloudresourcemanager_v3.Schema$Binding = {
        role: request.roleId,
        members: [request.member],
        condition: request.condition,
      };
      bindingList.push(newBinding);
      policy.bindings = bindingList;
    }

    await policyRouter.setPolicy(request.projectId, policy, request.target);
  };

  const removeMember = async (
    request: RemoveMemberRequest
  ): Promise<boolean> => {
    const policy = await policyRouter.getPolicy({
      ...request.target,
      projectId: request.projectId,
    });

    const bindingList = policy.bindings ?? [];

    // helper function that takes in a binding and returns true
    // if the binding was created by this request
    const matchBinding = (b: cloudresourcemanager_v3.Schema$Binding) => {
      if (!request.condition) {
        logger.debug({ request }, "No condition; matching on role only");
        return b.role === request.roleId && !b.condition;
      }

      // if there is a condition, check whether we have the correct binding
      // by matching based on the condition title. Condition content is ignored
      logger.debug({ request }, "Matching on both role and condition");
      return (
        b.role === request.roleId &&
        b.condition?.title === request.condition.title
      );
    };

    const binding = bindingList.find(matchBinding);

    // Three possibilities:
    // 1. Binding exists, includes member (remove member)
    // 2. Binding exists, does not include member (do nothing)
    // 3. Binding doesn't exist (do nothing)
    // Additionally, remove the binding altogether if it is empty after this operation

    if (!binding) {
      logger.info({ request }, "Role has no binding; skipping member removal");
      return isRoleEmpty(request.roleId, policy);
    }

    const memberList = binding.members ?? [];
    if (!memberList.includes(request.member)) {
      logger.info(
        { request },
        "Role is not granted to member; skipping member removal"
      );
      return isRoleEmpty(request.roleId, policy);
    }

    binding.members = memberList.filter((m) => m !== request.member);
    if (binding.members.length === 0) {
      logger.info({ request }, "Role is now empty; removing binding");
      policy.bindings = bindingList.filter((b) => !matchBinding(b));
    }

    await policyRouter.setPolicy(request.projectId, policy, request.target);

    return isRoleEmpty(request.roleId, policy);
  };

  const isRoleEmpty = (role: string, policy: iam_v1.Schema$Policy): boolean => {
    const binding = policy.bindings?.find(
      (binding) =>
        binding.role === role && binding.members && binding.members.length > 0
    );
    return !binding;
  };

  return {
    addMember,
    removeMember,
  };
}
