import type { UserProvisioningSecurityPerimeter } from "./client.ts";
import type { UserProvisioningSchema } from "./schema.ts";

/**
 * Validation functions that check if a user is namespaced, i.e. is marked
 * in some way that we can be sure that P0 created them.
 *
 * For example, this might check if the username has a specific prefix `p0_`.
 *
 * @group User
 */
type NamespaceValidation<Schema extends UserProvisioningSchema> = {
  userIsNamespacedById: (username: Schema["UserId"]) => Promise<boolean>;
  userIsNamespacedByBody: (username: Schema["UserBody"]) => Promise<boolean>;
};

/**
 * The primitives a specific connector must implement — lower-level, less
 * constrained building blocks than {@link UserProvisioningSecurityPerimeter}.
 * {@link buildUserProvisioningSecurityPerimeter} folds these into that perimeter.
 *
 * The namespacing guards (`userIsNamespacedByBody`, `userIsNamespacedById`) run
 * on every verb that touches a user, so P0-ownership is always checked.
 * `isEligible` runs only in `provision`, before the user is created.
 *
 * @summary The low-level primitives a connector implements to deliver a user-provisioning security perimeter.
 * @category High-Level
 */
export type UserProvisioningConnectorPrimitives<
  Schema extends UserProvisioningSchema,
> = {
  /**
   * Returns whether the given user is permitted to be provisioned. Called by
   * `provision` before any mutation; this is the provisioning eligibility
   * hook. The abstraction only declares and invokes it; each connector decides
   * *how* eligibility is determined.
   *
   * @group Eligibility
   */
  isEligible: (
    context: Schema["RequestContext"],
    userBody: Schema["UserBody"]
  ) => Promise<boolean>;

  /**
   * Returns namespace validation functions that check if a user is namespaced, i.e. is marked
   * in some way that we can be sure that P0 created them.
   *
   * For example, this might check if the username has a specific prefix `p0_`.
   *
   * If the return value is null, the user namespace checks will
   * be skipped. Some integrations have constraints on the target system that make
   * it impractical or impossible to namespace users. A known example is Postgres
   * via GCP CloudSQL, where the provisioned user in the database is just the user's
   * email address. However, in general this should always be included.
   *
   * @group User
   */
  validation: (
    context: Schema["RequestContext"]
  ) => NamespaceValidation<Schema> | null;

  /**
   * Gets a user with the given body, if they exist. `null` means it is safe to create.
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
   * @group User
   */
  deleteUser: (
    context: Schema["RequestContext"],
    username: Schema["UserId"]
  ) => Promise<void>;
};

/** @deprecated Use {@link UserProvisioningConnectorPrimitives}. */
export type UserProvisioningConnectorContract<
  Schema extends UserProvisioningSchema,
> = UserProvisioningConnectorPrimitives<Schema>;

/** @deprecated Use {@link UserProvisioningConnectorPrimitives}. */
export type UserProvisioningAtomicMethods<
  Schema extends UserProvisioningSchema,
> = UserProvisioningConnectorPrimitives<Schema>;

/**
 * Builds a {@link UserProvisioningSecurityPerimeter} from a connector's
 * {@link UserProvisioningConnectorPrimitives}.
 *
 * @summary Builds a user-provisioning security perimeter from a connector's implementation contract.
 * @category High-Level
 */
export const buildUserProvisioningSecurityPerimeter = <
  Schema extends UserProvisioningSchema,
>(
  methods: UserProvisioningConnectorPrimitives<Schema>
): UserProvisioningSecurityPerimeter<Schema> => ({
  provision: async ({ userBody, context }) => {
    if (!(await methods.isEligible(context, userBody))) {
      throw new Error("User is not eligible for provisioning");
    }
    const { userIsNamespacedByBody } = methods.validation(context) ?? {};
    if (userIsNamespacedByBody && !(await userIsNamespacedByBody(userBody))) {
      throw new Error("User is not namespaced");
    }
    const existing = await methods.getUser(context, userBody);
    if (existing !== null) return existing;
    return await methods.createUser(context, userBody);
  },

  identify: async ({ userBody, context }) => {
    const { userIsNamespacedByBody } = methods.validation(context) ?? {};
    if (userIsNamespacedByBody && !(await userIsNamespacedByBody(userBody))) {
      throw new Error("User is not namespaced");
    }
    return await methods.getUser(context, userBody);
  },

  deprovision: async ({ userId, context }) => {
    const { userIsNamespacedById } = methods.validation(context) ?? {};
    if (userIsNamespacedById && !(await userIsNamespacedById(userId))) {
      throw new Error("User is not namespaced");
    }
    await methods.deleteUser(context, userId);
    return null;
  },
});

/** @deprecated Use {@link buildUserProvisioningSecurityPerimeter}. */
export const userProvisioningImpl = buildUserProvisioningSecurityPerimeter;
