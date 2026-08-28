import type { ResourceRootSecurityPerimeter } from "./client.ts";
import type { ResourceRootSchema } from "./schema.ts";

/**
 * Validation functions that check if a user is namespaced, i.e. is marked
 * in some way that we can be sure that P0 created them.
 *
 * For example, this might check if the username has a specific prefix `p0_`.
 *
 * @group User
 */
type UserNamespaceValidation<Schema extends ResourceRootSchema> = {
  userIsNamespacedById: (username: Schema["UserId"]) => Promise<boolean>;
  userIsNamespacedByBody: (username: Schema["UserBody"]) => Promise<boolean>;
};

/**
 * The primitives a specific connector must implement — lower-level, less
 * constrained building blocks than {@link ResourceRootSecurityPerimeter}.
 * {@link buildResourceRootSecurityPerimeter} folds these into that perimeter.
 *
 * @summary The low-level primitives a connector implements to deliver a resource-root security perimeter.
 * @category High-Level
 */
export type ResourceRootConnectorPrimitives<Schema extends ResourceRootSchema> =
  {
    /**
     * Returns namespace validation functions that check user namespacing.
     *
     * If the returned user field is null, the check will
     * be skipped. Some integrations have constraints on the target system that make
     * it impractical or impossible to namespace users. A known example is Postgres
     * via GCP CloudSQL, where the provisioned user in the database is just the user's
     * email address. However, in general this should always be included.
     */
    validation: (context: Schema["RequestContext"]) => {
      user: UserNamespaceValidation<Schema> | null;
    };

    /**
     * Gets a user with the given body, if they exist. If this returns `null`,
     * it should be safe to create the user.
     *
     * @group User
     */
    getUser: (
      context: Schema["RequestContext"],
      username: Schema["UserBody"]
    ) => Promise<Schema["UserId"] | null>;

    /**
     * Creates a user with the given body.
     *
     * @group User
     */
    createUser: (
      context: Schema["RequestContext"],
      username: Schema["UserBody"]
    ) => Promise<Schema["UserId"]>;

    /**
     * Deletes a user with the given ID.
     *
     * If users cannot or should not be deleted, this can be a no-op.
     *
     * @group User
     */
    deleteUser: (
      context: Schema["RequestContext"],
      username: Schema["UserId"]
    ) => Promise<void>;

    /**
     * Sets the full policy set on a user, replacing whatever was previously set.
     *
     * @group Resource
     */
    setPoliciesForUser: (
      context: Schema["RequestContext"],
      userId: Schema["UserId"],
      policies: Schema["Policy"][]
    ) => Promise<void>;

    list: (query: Schema["ListerQuery"]) => Promise<Schema["ListerResponse"]>;
  };

/** @deprecated Use {@link ResourceRootConnectorPrimitives}. */
export type ResourceRootConnectorContract<Schema extends ResourceRootSchema> =
  ResourceRootConnectorPrimitives<Schema>;

/** @deprecated Use {@link ResourceRootConnectorPrimitives}. */
export type ResourceRootAtomicMethods<Schema extends ResourceRootSchema> =
  ResourceRootConnectorPrimitives<Schema>;

/**
 * Builds a {@link ResourceRootSecurityPerimeter} from a connector's
 * {@link ResourceRootConnectorPrimitives}.
 *
 * @summary Builds a resource-root security perimeter from a connector's implementation contract.
 */
export const buildResourceRootSecurityPerimeter = <
  Schema extends ResourceRootSchema,
>(
  methods: ResourceRootConnectorPrimitives<Schema>
): ResourceRootSecurityPerimeter<Schema> => ({
  provisionUser: async ({ userBody, context }) => {
    const { userIsNamespacedByBody } = methods.validation(context).user ?? {};
    if (userIsNamespacedByBody && !(await userIsNamespacedByBody(userBody))) {
      throw new Error(`Username ${JSON.stringify(userBody)} is not namespaced`);
    }

    return (
      (await methods.getUser(context, userBody)) ??
      (await methods.createUser(context, userBody))
    );
  },

  identifyUser: async ({ userBody, context }) => {
    const { userIsNamespacedByBody } = methods.validation(context).user ?? {};
    if (userIsNamespacedByBody && !(await userIsNamespacedByBody(userBody))) {
      throw new Error(`Username ${JSON.stringify(userBody)} is not namespaced`);
    }
    return await methods.getUser(context, userBody);
  },

  deleteUser: async ({ userId, context }) => {
    const { userIsNamespacedById } = methods.validation(context).user ?? {};

    if (userIsNamespacedById && !(await userIsNamespacedById(userId))) {
      throw new Error(`Resource ${userId} is not namespaced`);
    }
    await methods.deleteUser(context, userId);

    return null;
  },

  setPoliciesForUser: async ({ userId, policies, context }) => {
    const { userIsNamespacedById } = methods.validation(context).user ?? {};

    if (userIsNamespacedById && !(await userIsNamespacedById(userId))) {
      throw new Error(`Resource ${userId} is not namespaced`);
    }
    await methods.setPoliciesForUser(context, userId, policies);

    return null;
  },

  list: async ({ query }) => await methods.list(query),
});

/** @deprecated Use {@link buildResourceRootSecurityPerimeter}. */
export const ResourceRootImpl = buildResourceRootSecurityPerimeter;
