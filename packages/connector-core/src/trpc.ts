import { createTRPCClient } from "@trpc/client";
import type { AnyRouter } from "@trpc/server";
import { initTRPC } from "@trpc/server";

import { connectorErrorFormatter } from "./errors/index.ts";
import type { ResourceRootRouter } from "./index.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "./securityPerimeters/common/trpc.ts";
import type { ResourceHierarchyRouter } from "./securityPerimeters/resourceHierarchy/trpc.ts";
import type { SecretManagementRouter } from "./securityPerimeters/secretManagement/trpc.ts";
import type { UserProvisioningRouter } from "./securityPerimeters/userProvisioning/trpc.ts";

export type { ConnectorContext } from "./securityPerimeters/common/trpc.ts";

/**
 * Builds the tRPC root instance a connector should use
 */
export const newConnectorTRPC = () =>
  initTRPC.context<ConnectorContext>().create({
    errorFormatter: connectorErrorFormatter,
  });

// Access routers come in different abstract shapes; the connector router
// accepts any of them.
type AccessRouterTypes =
  | ResourceHierarchyRouter<any>
  | ResourceRootRouter<any>
  | SecretManagementRouter<any>
  | UserProvisioningRouter<any>;

/**
 * Builds a single-entry record, preserving `key` as a literal type instead of
 * widening to a `{ [x: string]: V }` index signature. A computed property key
 * is the one case TS can't type precisely on its own, so the assertion is
 * contained here rather than repeated at call sites.
 */
const singleEntryRecord = <Key extends string, Value>(
  key: Key,
  value: Value
): Record<Key, Value> => ({ [key]: value }) as Record<Key, Value>;

export const newConnectorRouter = <
  Namespace extends string = string,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  AccessRouters extends Record<string, AccessRouterTypes> = {},
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
>(
  namespace: Namespace,
  t: TRPCInstance,
  accesses: AccessRouters,
  install: InstallRouter,
  metadata: MetadataRouter
) => {
  const { router } = t;
  const namespaced = router({
    accesses: router(accesses),
    install,
    metadata,
  });
  return router(singleEntryRecord(namespace, namespaced));
};

/**
 * Defines the complete type representation of the TRPC router on the connector
 * @summary Defines the complete type representation of the TRPC router on the connector
 *
 */
export type ConnectorRouter<
  Namespace extends string = string,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  AccessLifecycleRouters extends Record<string, AccessRouterTypes> = {},
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
> = ReturnType<
  typeof newConnectorRouter<
    Namespace,
    TRPCInstance,
    AccessLifecycleRouters,
    InstallRouter,
    MetadataRouter
  >
>;

/**
 * Creates a TRPC client for a defined {@link ConnectorRouter}
 * @summary Creates a TRPC client for a defined {@link ConnectorRouter}
 */
export const newTRPCConnectorClient = <ConnectorRouter extends AnyRouter>(
  opts: Parameters<typeof createTRPCClient<ConnectorRouter>>[0]
) => {
  return createTRPCClient<ConnectorRouter>(opts);
};
