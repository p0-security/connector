/**
 * The finite, enumerable set of operations a connector exposes to the P0
 * control plane — the actual security boundary, regardless of how the
 * connector itself is deployed or permissioned.
 *
 * Concrete perimeters: {@link ResourceHierarchySecurityPerimeter},
 * {@link ResourceRootSecurityPerimeter}, {@link SecretManagementSecurityPerimeter},
 * {@link UserProvisioningSecurityPerimeter}. Each is built from a connector's
 * `*ConnectorPrimitives` by a `build*SecurityPerimeter` function.
 *
 * Identity alias — no runtime effect.
 *
 * @category High-Level
 */
export type SecurityPerimeter<
  Operations extends Record<string, (...args: any[]) => Promise<any>>,
> = Operations;
