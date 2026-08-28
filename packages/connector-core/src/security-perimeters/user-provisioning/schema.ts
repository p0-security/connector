import type { JsonValue } from "type-fest";

import type { UserProvisioningSecurityPerimeter } from "./client.ts";
import type { UserProvisioningConnectorPrimitives } from "./implementation.ts";
import type { UserProvisioningParsers } from "./parsers.ts";

/**
 * The types used by {@link UserProvisioningSecurityPerimeter}.
 *
 * User lifecycle only — no resources, policies, or bindings. Generic and
 * IdP-agnostic: nothing provider-specific may appear here.
 *
 * @summary The types used by {@link UserProvisioningSecurityPerimeter}.
 * @category High-Level
 */
export type UserProvisioningSchema<
  User extends JsonValue = JsonValue,
  RequestContext extends JsonValue & { requestId: string } = JsonValue & {
    requestId: string;
  },
> = {
  /** A request to provision/identify a user. */
  UserBody: User;
  /** The identifier of a provisioned user. */
  UserId: string;
  /** The request context with any other data needed for user provisioning/deprovisioning. */
  RequestContext: RequestContext;
};

/**
 * Extracts the {@link UserProvisioningSchema} from a UserProvisioning related type.
 *
 * @summary Extracts the {@link UserProvisioningSchema} from a UserProvisioning related type.
 * @category High-Level
 */
export type UserProvisioningSchemaOf<T> =
  T extends UserProvisioningSecurityPerimeter<infer Types>
    ? Types
    : T extends UserProvisioningConnectorPrimitives<infer Types>
      ? Types
      : T extends UserProvisioningParsers<infer Types>
        ? Types
        : never;
