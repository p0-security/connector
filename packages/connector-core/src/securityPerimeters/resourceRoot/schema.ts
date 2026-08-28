import type { JsonValue } from "type-fest";

import type { SelectItem } from "../../listing/types.ts";
import type { ResourceRootSecurityPerimeter } from "./client.ts";
import type { ResourceRootConnectorPrimitives } from "./implementation.ts";
import type { ResourceRootParsers } from "./parsers.ts";

/**
 * The types used by {@link ResourceRootSecurityPerimeter}.
 *
 * @summary The types used by {@link ResourceRootSecurityPerimeter}.
 * @category High-Level
 */
export type ResourceRootSchema<
  User extends JsonValue = JsonValue,
  Policy extends JsonValue = JsonValue,
  ListerQuery extends JsonValue & { type: string } = JsonValue & {
    type: string;
  },
  RequestContext extends JsonValue & { requestId: string } = JsonValue & {
    requestId: string;
  },
> = {
  /** A request to create a user. */
  UserBody: User;
  /** The result of creating a user. */
  UserId: string;
  /** A policy applied to a resource. */
  Policy: Policy;
  /** The lister query */
  ListerQuery: ListerQuery;
  /** The pagination response */
  ListerResponse: SelectItem[];
  /** The request context with any other data needed for access provisioning/deprovisioning */
  RequestContext: RequestContext;
};

/**
 * Extracts the {@link ResourceRootSchema} from a ResourceRoot related type.
 *
 * For future-proofing, pass a {@link ResourceRootSecurityPerimeter} type when possible.
 *
 * @summary Extracts the {@link ResourceRootSchema} from a ResourceRoot related type.
 * @category High-Level
 */
export type ResourceRootSchemaOf<T> =
  T extends ResourceRootSecurityPerimeter<infer Types>
    ? Types
    : T extends ResourceRootConnectorPrimitives<infer Types>
      ? Types
      : T extends ResourceRootParsers<infer Types>
        ? Types
        : never;
