import { createTRPCClient } from "@trpc/client";
import type { AnyRouter } from "@trpc/server";
import { initTRPC } from "@trpc/server";

import { connectorErrorFormatter } from "./errors/index.ts";
import type { ResourceRootRouter } from "./index.ts";
import type {
  AnyConnectorTRPCInstance,
  ConnectorContext,
} from "./security-perimeters/common/trpc.ts";
import type { ResourceHierarchyRouter } from "./security-perimeters/resource-hierarchy/trpc.ts";
import type { SecretManagementRouter } from "./security-perimeters/secret-management/trpc.ts";
import type { UserProvisioningRouter } from "./security-perimeters/user-provisioning/trpc.ts";

export type { ConnectorContext } from "./security-perimeters/common/trpc.ts";

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

/** The routes under a connector's namespace; `logs` only when the connector reads logs. */
type NamespacedRoutes<
  AccessRouters,
  InstallRouter,
  MetadataRouter,
  LogsRouter,
> = {
  accesses: AccessRouters;
  install: InstallRouter;
  metadata: MetadataRouter;
} & (LogsRouter extends AnyRouter ? { logs: LogsRouter } : unknown);

export const newConnectorRouter = <
  Namespace extends string = string,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  AccessRouters extends Record<string, AccessRouterTypes> = {},
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
  LogsRouter extends AnyRouter | undefined = undefined,
>(
  namespace: Namespace,
  t: TRPCInstance,
  accesses: AccessRouters,
  install: InstallRouter,
  metadata: MetadataRouter,
  /** A log-source connector's `logs` router, from {@link newLogsRouter}. */
  logs?: LogsRouter
) => {
  const { router } = t;
  const accessesRouter = router(accesses);
  // The conditional route type can't be checked against the branch taken at
  // runtime, so the assertion is contained here.
  const routes = (
    logs === undefined
      ? { accesses: accessesRouter, install, metadata }
      : { accesses: accessesRouter, install, metadata, logs }
  ) as NamespacedRoutes<
    typeof accessesRouter,
    InstallRouter,
    MetadataRouter,
    LogsRouter
  >;
  const namespaced = router(routes);
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
  LogsRouter extends AnyRouter | undefined = undefined,
> = ReturnType<
  typeof newConnectorRouter<
    Namespace,
    TRPCInstance,
    AccessLifecycleRouters,
    InstallRouter,
    MetadataRouter,
    LogsRouter
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
