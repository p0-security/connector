import type { JsonValue } from "type-fest";

import type { SelectItem } from "../../listing/types.ts";
import type { ResourceHierarchySecurityPerimeter } from "./client.ts";
import type { ResourceHierarchyConnectorPrimitives } from "./implementation.ts";
import type { ResourceHierarchyParsers } from "./parsers.ts";

/**
 * The types used by {@link ResourceHierarchyApiMethods}.
 *
 * @summary The types used by {@link ResourceHierarchyApiMethods}.
 * @category High-Level
 */
export type ResourceHierarchySchema<
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
  /** A request to create a resource. */
  ResourceBody: string;
  /** A policy applied to a resource. */
  Policy: Policy;
  /** The result of creating a resource. */
  ResourceId: string;
  /** The lister query */
  ListerQuery: ListerQuery;
  /** The pagination response */
  ListerResponse: SelectItem[];
  /** The request context with any other data needed for access provisioning/deprovisioning */
  RequestContext: RequestContext;
};

/**
 * Extracts the {@link ResourceHierarchySchema} from a ResourceHierarchy related type.
 *
 * For future-proofing, pass a {@link ResourceHierarchySecurityPerimeter} type when possible.
 *
 * @summary Extracts the {@link ResourceHierarchySchema} from a ResourceHierarchy related type.
 * @category High-Level
 */
export type ResourceHierarchySchemaOf<T> =
  T extends ResourceHierarchySecurityPerimeter<infer Types>
    ? Types
    : T extends ResourceHierarchyConnectorPrimitives<infer Types>
      ? Types
      : T extends ResourceHierarchyParsers<infer Types>
        ? Types
        : never;
