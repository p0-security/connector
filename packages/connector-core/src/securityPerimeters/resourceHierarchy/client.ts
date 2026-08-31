import type { TRPCClient } from "@trpc/client";

import { action } from "../common/client.ts";
import type { SecurityPerimeter } from "../common/securityPerimeter.ts";
import type { ResourceHierarchyParsers } from "./parsers.ts";
import type { ResourceHierarchySchema } from "./schema.ts";
import type { ResourceHierarchyRouter } from "./trpc.ts";

/**
 * The security perimeter for a resource-hierarchy connector: provision users
 * and create, update policies on, bind, and delete access resources
 * beneath them.
 *
 * @summary The security perimeter for a resource-hierarchy connector.
 * @category High-Level
 */
export type ResourceHierarchySecurityPerimeter<
  Schema extends ResourceHierarchySchema = ResourceHierarchySchema,
> = SecurityPerimeter<{
  /**
   * Identifies a user in the security perimeter.
   * @param params The parameters for identifying the user.
   * @returns A promise that resolves with the user ID.
   */
  identifyUser: (params: {
    userBody: Schema["UserBody"];
    context: Schema["RequestContext"];
  }) => Promise<Schema["UserId"] | null>;

  /**
   * Provisions a user in the security perimeter.
   * @param params The parameters for provisioning the user.
   * @returns A promise that resolves with the user ID.
   */
  provisionUser: (params: {
    userBody: Schema["UserBody"];
    context: Schema["RequestContext"];
  }) => Promise<Schema["UserId"]>;

  /**
   * Creates an access resource in the security perimeter.
   * @param params The parameters for creating the access resource.
   * @returns A promise that resolves with the resource ID.
   */
  createAccessResource: (params: {
    resourceBody: Schema["ResourceBody"];
    context: Schema["RequestContext"];
  }) => Promise<Schema["ResourceId"]>;

  deleteAccessResource: (params: {
    resourceId: Schema["ResourceId"];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  addPoliciesToResource: (params: {
    resourceId: Schema["ResourceId"];
    policies: Schema["Policy"][];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  removePoliciesFromResource: (params: {
    resourceId: Schema["ResourceId"];
    policies: Schema["Policy"][];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  bindAccessResource: (params: {
    userId: Schema["UserId"];
    resourceId: Schema["ResourceId"];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  unbindAccessResource: (params: {
    userId: Schema["UserId"];
    resourceId: Schema["ResourceId"];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  list: (params: {
    query: Schema["ListerQuery"];
  }) => Promise<Schema["ListerResponse"]>;
}>;

/** @deprecated Use {@link ResourceHierarchySecurityPerimeter}. */
export type ResourceHierarchyApiMethods<
  Schema extends ResourceHierarchySchema = ResourceHierarchySchema,
> = ResourceHierarchySecurityPerimeter<Schema>;

export type ResourceHierarchyEndpoint =
  keyof ResourceHierarchySecurityPerimeter;

/**
 * Wraps the {@link ResourceHierarchySecurityPerimeter} with return-value validation on the P0 control plane
 *
 * @summary Wraps the {@link ResourceHierarchySecurityPerimeter} with return-value validation on the P0 control plane
 * @category High-Level
 */
export const newResourceHierarchyConnectorMethods = <
  Schema extends ResourceHierarchySchema,
>(
  parsers: ResourceHierarchyParsers<Schema>,
  scopedClient: Pick<
    TRPCClient<ResourceHierarchyRouter<Schema>>,
    ResourceHierarchyEndpoint
  >
) => {
  // prettier-ignore
  return {
    identifyUser: action(scopedClient.identifyUser.mutate, (x: unknown) => x === null ? null : parsers.userId(x)),
    provisionUser: action(scopedClient.provisionUser.mutate, parsers.userId),
    addPoliciesToResource: action(scopedClient.addPoliciesToResource.mutate, () => null),
    removePoliciesFromResource: action(scopedClient.removePoliciesFromResource.mutate, () => null),
    createAccessResource: action(scopedClient.createAccessResource.mutate, parsers.resourceId),
    deleteAccessResource: action(scopedClient.deleteAccessResource.mutate, () => null),
    bindAccessResource: action(scopedClient.bindAccessResource.mutate, () => null),
    unbindAccessResource: action(scopedClient.unbindAccessResource.mutate, () => null),
    list: action(scopedClient.list.query, parsers.listerResponse),
  };
};
