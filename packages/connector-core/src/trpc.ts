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

/** The routes every connector serves, whatever it connects P0 to. */
type CommonRoutes<
  InstallRouter extends AnyRouter,
  MetadataRouter extends AnyRouter,
> = {
  install: InstallRouter;
  metadata: MetadataRouter;
};

/**
 * The routes of a connector that provisions access in a resource
 * integration: one access router per access type, under `accesses`.
 */
export type ResourceIntegrationRoutes<
  AccessRouters extends Record<string, AccessRouterTypes> = Record<
    string,
    AccessRouterTypes
  >,
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
> = CommonRoutes<InstallRouter, MetadataRouter> & { accesses: AccessRouters };

/**
 * The routes of a connector that reads access logs: the `logs` router from
 * {@link newLogsRouter}.
 */
export type AccessLogsRoutes<
  LogsRouter extends AnyRouter = AnyRouter,
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
> = CommonRoutes<InstallRouter, MetadataRouter> & { logs: LogsRouter };

/** The routes a connector serves under its namespace. */
export type ConnectorRoutes = AccessLogsRoutes | ResourceIntegrationRoutes;

/**
 * Builds a connector's root router, which serves `routes` under `namespace`.
 *
 * `accesses` is a plain record of routers; tRPC mounts a nested record exactly
 * as it would the router built from it.
 */
export const newConnectorRouter = <
  Namespace extends string = string,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  Routes extends ConnectorRoutes = ConnectorRoutes,
>(
  namespace: Namespace,
  t: TRPCInstance,
  routes: Routes
) => t.router(singleEntryRecord(namespace, routes));

/**
 * Defines the complete type representation of a resource integration
 * connector's TRPC router
 */
export type ResourceIntegrationConnectorRouter<
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
    ResourceIntegrationRoutes<
      AccessLifecycleRouters,
      InstallRouter,
      MetadataRouter
    >
  >
>;

/**
 * Defines the complete type representation of an access logs connector's
 * TRPC router
 */
export type AccessLogsConnectorRouter<
  Namespace extends string = string,
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  LogsRouter extends AnyRouter = AnyRouter,
  InstallRouter extends AnyRouter = AnyRouter,
  MetadataRouter extends AnyRouter = AnyRouter,
> = ReturnType<
  typeof newConnectorRouter<
    Namespace,
    TRPCInstance,
    AccessLogsRoutes<LogsRouter, InstallRouter, MetadataRouter>
  >
>;

/**
 * Defines the complete type representation of the TRPC router on the
 * connector.
 *
 * Without `AccessLifecycleRouters`, it covers either kind of connector, so
 * it can stand for any connector (a client that only calls `metadata`).
 * Given access routers, it is a resource integration connector's router, so
 * a client typed with it still sees `accesses`.
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
> =
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  {} extends AccessLifecycleRouters
    ? | AccessLogsConnectorRouter<
          Namespace,
          TRPCInstance,
          AnyRouter,
          InstallRouter,
          MetadataRouter
        >
      | ResourceIntegrationConnectorRouter<
          Namespace,
          TRPCInstance,
          AccessLifecycleRouters,
          InstallRouter,
          MetadataRouter
        >
    : ResourceIntegrationConnectorRouter<
        Namespace,
        TRPCInstance,
        AccessLifecycleRouters,
        InstallRouter,
        MetadataRouter
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
