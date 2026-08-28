import type { TRPCClient } from "@trpc/client";

import { action } from "../common/client.ts";
import type { SecurityPerimeter } from "../common/security-perimeter.ts";
import type { UserProvisioningParsers } from "./parsers.ts";
import type { UserProvisioningSchema } from "./schema.ts";
import type { UserProvisioningRouter } from "./trpc.ts";

/**
 * The security perimeter for a user-provisioning connector: identify,
 * provision, and deprovision users.
 *
 * @summary The security perimeter for a user-provisioning connector.
 * @category High-Level
 */
export type UserProvisioningSecurityPerimeter<
  Schema extends UserProvisioningSchema = UserProvisioningSchema,
> = SecurityPerimeter<{
  /**
   * Identifies a user, returning their ID if they exist or `null` otherwise.
   */
  identify: (params: {
    userBody: Schema["UserBody"];
    context: Schema["RequestContext"];
  }) => Promise<Schema["UserId"] | null>;

  /**
   * Provisions a user (idempotent: returns the existing user if present,
   * otherwise creates one). Rejects if the user is not eligible.
   */
  provision: (params: {
    userBody: Schema["UserBody"];
    context: Schema["RequestContext"];
  }) => Promise<Schema["UserId"]>;

  /**
   * Deprovisions (deletes) a previously provisioned user.
   */
  deprovision: (params: {
    userId: Schema["UserId"];
    context: Schema["RequestContext"];
  }) => Promise<null>;
}>;

/** @deprecated Use {@link UserProvisioningSecurityPerimeter}. */
export type UserProvisioningApiMethods<
  Schema extends UserProvisioningSchema = UserProvisioningSchema,
> = UserProvisioningSecurityPerimeter<Schema>;

export type UserProvisioningEndpoint = keyof UserProvisioningSecurityPerimeter;

/**
 * Wraps the {@link UserProvisioningSecurityPerimeter} with return-value validation on the P0 control plane
 *
 * @summary Wraps the {@link UserProvisioningSecurityPerimeter} with return-value validation on the P0 control plane
 * @category High-Level
 */
export const newUserProvisioningConnectorMethods = <
  Schema extends UserProvisioningSchema,
>(
  parsers: UserProvisioningParsers<Schema>,
  scopedClient: Pick<
    TRPCClient<UserProvisioningRouter<Schema>>,
    UserProvisioningEndpoint
  >
) => {
  // prettier-ignore
  return {
    identify: action(scopedClient.identify.mutate, (x: unknown) => x === null ? null : parsers.userId(x)),
    provision: action(scopedClient.provision.mutate, parsers.userId),
    deprovision: action(scopedClient.deprovision.mutate, () => null),
  };
};
