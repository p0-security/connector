import type { ResourceHierarchySecurityPerimeter } from "./client.ts";
import type { ResourceHierarchySchema } from "./schema.ts";

/**
 * Validation functions that check if a user is namespaced, i.e. is marked
 * in some way that we can be sure that P0 created them.
 *
 * For example, this might check if the username has a specific prefix `p0_`.
 *
 * @group User
 */
type UserNamespaceValidation<Schema extends ResourceHierarchySchema> = {
  userIsNamespacedById: (username: Schema["UserId"]) => Promise<boolean>;
  userIsNamespacedByBody: (username: Schema["UserBody"]) => Promise<boolean>;
};

/**
 * Validation functions that check if an access resource is namespaced, i.e. is marked
 * in some way that we can be sure that P0 created them.
 *
 * For example, in AWS this might check if the resource is tagged with `ManagedBy: P0Security`.
 *
 * @group Resource
 */
type ResourceNamespaceValidation<Schema extends ResourceHierarchySchema> = {
  resourceIsNamespacedById: (
    resource: Schema["ResourceId"]
  ) => Promise<boolean>;
  resourceIsNamespacedByBody: (
    resource: Schema["ResourceBody"]
  ) => Promise<boolean>;
};

/**
 * The primitives a specific connector must implement — lower-level, less
 * constrained building blocks than {@link ResourceHierarchySecurityPerimeter}.
 * {@link buildResourceHierarchySecurityPerimeter} folds these into that perimeter.
 *
 * @summary The low-level primitives a connector implements to deliver a resource-hierarchy security perimeter.
 * @category High-Level
 */
export type ResourceHierarchyConnectorPrimitives<
  Schema extends ResourceHierarchySchema,
> = {
  /**
   * Returns namespace validation functions that check for user and access resource namespacing
   *
   * If the returned user or resource field is null, that check will
   * be skipped. Some integrations have constraints on the target system that make
   * it impractical or impossible to namespace users. A known example is Postgres
   * via GCP CloudSQL, where the provisioned user in the database is just the user's
   * email address. However, in general this should always be included.
   */
  validation: (context: Schema["RequestContext"]) => {
    user: UserNamespaceValidation<Schema> | null;
    resource: ResourceNamespaceValidation<Schema> | null;
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
   * Creates an access resource with the given body.
   *
   * @group Resource
   */
  createResource: (
    context: Schema["RequestContext"],
    resourceBody: Schema["ResourceBody"]
  ) => Promise<Schema["ResourceId"]>;
  /**
   * Adds a policy to an access resource with the given ID.
   *
   * @group Resource
   */
  addPolicyToResource: (
    context: Schema["RequestContext"],
    resourceBody: Schema["ResourceId"],
    policy: Schema["Policy"]
  ) => Promise<void>;

  /**
   * Removes a policy from an access resource with the given ID.
   *
   * @group Resource
   */
  removePolicyFromResource: (
    context: Schema["RequestContext"],
    resourceId: Schema["ResourceId"],
    policy: Schema["Policy"]
  ) => Promise<void>;

  /**
   * Deletes an access resource with the given ID.
   *
   * @group Resource
   */
  deleteResource: (
    context: Schema["RequestContext"],
    resource: Schema["ResourceId"]
  ) => Promise<void>;

  /**
   * Binds an access resource to a user, returning a binding ID.
   *
   * @group Bindings
   */
  bindResourceToUser: (
    context: Schema["RequestContext"],
    resource: Schema["ResourceId"],
    user: Schema["UserId"]
  ) => Promise<void>;

  /**
   * Unbinds an access resource from a user using the given binding ID.
   *
   * @group Bindings
   */
  unbindResourceFromUser: (
    context: Schema["RequestContext"],
    resource: Schema["ResourceId"],
    user: Schema["UserId"]
  ) => Promise<void>;

  list: (query: Schema["ListerQuery"]) => Promise<Schema["ListerResponse"]>;
};

/** @deprecated Use {@link ResourceHierarchyConnectorPrimitives}. */
export type ResourceHierarchyConnectorContract<
  Schema extends ResourceHierarchySchema,
> = ResourceHierarchyConnectorPrimitives<Schema>;

/** @deprecated Use {@link ResourceHierarchyConnectorPrimitives}. */
export type ResourceHierarchyAtomicMethods<
  Schema extends ResourceHierarchySchema,
> = ResourceHierarchyConnectorPrimitives<Schema>;

/**
 * Builds a {@link ResourceHierarchySecurityPerimeter} from a connector's
 * {@link ResourceHierarchyConnectorPrimitives}.
 *
 * @summary Builds a resource-hierarchy security perimeter from a connector's implementation contract.
 */
export const buildResourceHierarchySecurityPerimeter = <
  Schema extends ResourceHierarchySchema,
>(
  methods: ResourceHierarchyConnectorPrimitives<Schema>
): ResourceHierarchySecurityPerimeter<Schema> => ({
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

  createAccessResource: async ({ resourceBody, context }) => {
    const { resourceIsNamespacedByBody } =
      methods.validation(context).resource ?? {};

    if (
      resourceIsNamespacedByBody &&
      !(await resourceIsNamespacedByBody(resourceBody))
    ) {
      throw new Error(`Resource ${resourceBody} is not namespaced`);
    }

    return await methods.createResource(context, resourceBody);
  },

  addPoliciesToResource: async ({ resourceId, policies, context }) => {
    const { resourceIsNamespacedById } =
      methods.validation(context).resource ?? {};

    if (
      resourceIsNamespacedById &&
      !(await resourceIsNamespacedById(resourceId))
    ) {
      throw new Error(`Resource ${resourceId} is not namespaced`);
    }
    for (const policy of policies) {
      await methods.addPolicyToResource(context, resourceId, policy);
    }

    return null;
  },

  removePoliciesFromResource: async ({ resourceId, policies, context }) => {
    const { resourceIsNamespacedById } =
      methods.validation(context).resource ?? {};

    if (
      resourceIsNamespacedById &&
      !(await resourceIsNamespacedById(resourceId))
    ) {
      throw new Error(`Resource ${resourceId} is not namespaced`);
    }
    for (const policy of policies) {
      await methods.removePolicyFromResource(context, resourceId, policy);
    }

    return null;
  },

  bindAccessResource: async ({ userId, resourceId, context }) => {
    const validation = methods.validation(context);
    const { userIsNamespacedById } = validation.user ?? {};
    const { resourceIsNamespacedById } = validation.resource ?? {};

    if (userIsNamespacedById && !(await userIsNamespacedById(userId))) {
      throw new Error(`Username ${userId} is not namespaced`);
    }
    if (
      resourceIsNamespacedById &&
      !(await resourceIsNamespacedById(resourceId))
    ) {
      throw new Error(`Resource ${resourceId} is not namespaced`);
    }
    await methods.bindResourceToUser(context, resourceId, userId);
    return null;
  },

  unbindAccessResource: async ({ userId, resourceId, context }) => {
    const validation = methods.validation(context);
    const { userIsNamespacedById } = validation.user ?? {};
    const { resourceIsNamespacedById } = validation.resource ?? {};

    if (userIsNamespacedById && !(await userIsNamespacedById(userId))) {
      throw new Error(`Username ${userId} is not namespaced`);
    }

    if (
      resourceIsNamespacedById &&
      !(await resourceIsNamespacedById(resourceId))
    ) {
      throw new Error(`Resource ${resourceId} is not namespaced`);
    }
    await methods.unbindResourceFromUser(context, resourceId, userId);
    return null;
  },

  deleteAccessResource: async ({ resourceId, context }) => {
    const { resourceIsNamespacedById } =
      methods.validation(context).resource ?? {};

    if (
      resourceIsNamespacedById &&
      !(await resourceIsNamespacedById(resourceId))
    ) {
      throw new Error(`Resource ${resourceId} is not namespaced`);
    }
    await methods.deleteResource(context, resourceId);
    return null;
  },

  list: async ({ query }) => await methods.list(query),
});

/** @deprecated Use {@link buildResourceHierarchySecurityPerimeter}. */
export const resourceHierarchyImpl = buildResourceHierarchySecurityPerimeter;
