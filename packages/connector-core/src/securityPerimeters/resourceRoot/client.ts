import type { TRPCClient } from "@trpc/client";

import { action } from "../common/client.ts";
import type { SecurityPerimeter } from "../common/securityPerimeter.ts";
import type { ResourceRootParsers } from "./parsers.ts";
import type { ResourceRootSchema } from "./schema.ts";
import type { ResourceRootRouter } from "./trpc.ts";

/**
 * The security perimeter for a resource-root connector: provision/
 * deprovision users and manage the policies attached directly to them.
 *
 * @summary The security perimeter for a resource-root connector.
 * @category High-Level
 */
export type ResourceRootSecurityPerimeter<
  Schema extends ResourceRootSchema = ResourceRootSchema,
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
   * Deletes a user in the security perimeter.
   * @param params The parameters for deleting the user.
   */
  deleteUser: (params: {
    userId: Schema["UserId"];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  /**
   * Sets the full policy set on a user, replacing whatever was previously set.
   * @param params The parameters for setting the user's policies.
   */
  setPoliciesForUser: (params: {
    userId: Schema["UserId"];
    policies: Schema["Policy"][];
    context: Schema["RequestContext"];
  }) => Promise<null>;

  list: (params: {
    query: Schema["ListerQuery"];
  }) => Promise<Schema["ListerResponse"]>;
}>;

/** @deprecated Use {@link ResourceRootSecurityPerimeter}. */
export type ResourceRootApiMethods<
  Schema extends ResourceRootSchema = ResourceRootSchema,
> = ResourceRootSecurityPerimeter<Schema>;

export type ResourceRootEndpoint = keyof ResourceRootSecurityPerimeter;

/**
 * Wraps the {@link ResourceRootSecurityPerimeter} with return-value validation on the P0 control plane
 *
 * @summary Wraps the {@link ResourceRootSecurityPerimeter} with return-value validation on the P0 control plane
 * @category High-Level
 */
export const newResourceRootConnectorMethods = <
  Schema extends ResourceRootSchema,
>(
  parsers: ResourceRootParsers<Schema>,
  scopedClient: Pick<
    TRPCClient<ResourceRootRouter<Schema>>,
    ResourceRootEndpoint
  >
) => {
  // prettier-ignore
  return {
    identifyUser: action(scopedClient.identifyUser.mutate, (x: unknown) => x === null ? null : parsers.userId(x)),
    provisionUser: action(scopedClient.provisionUser.mutate, parsers.userId),
    deleteUser: action(scopedClient.deleteUser.mutate, () => null),
    setPoliciesForUser: action(scopedClient.setPoliciesForUser.mutate, () => null),
    list: action(scopedClient.list.query, parsers.listerResponse),
  };
};
