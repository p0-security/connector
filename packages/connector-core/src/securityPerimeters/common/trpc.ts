import type { TRPCRootObject } from "@trpc/server";

import type { Logger } from "../../logger.ts";

/** The tRPC context every connector's procedures receive; every `new*Router` builder in this package requires at least this much. */
export type ConnectorContext = { logger: Logger };

/** A tRPC root instance whose context satisfies {@link ConnectorContext}; the bound every `new*Router` builder in this package requires of its `t` parameter. */
export type AnyConnectorTRPCInstance = TRPCRootObject<
  ConnectorContext,
  any,
  any,
  any
>;
