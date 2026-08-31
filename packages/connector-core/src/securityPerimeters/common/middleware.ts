import type { SecurityPerimeter } from "./securityPerimeter.ts";
import type { AnyConnectorTRPCInstance, ConnectorContext } from "./trpc.ts";

/**
 * Wraps a connector's procedure builder so its security perimeter is built
 * once per request — from `buildSecurityPerimeter` — and exposed as
 * `ctx.perimeter` to every downstream handler.
 */
export const withSecurityPerimeter = <
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
  Operations extends Record<string, (...args: any[]) => Promise<any>> = Record<
    string,
    (...args: any[]) => Promise<any>
  >,
>(
  procedure: TRPCInstance["procedure"],
  buildSecurityPerimeter: (
    ctx: ConnectorContext
  ) => SecurityPerimeter<Operations>
) =>
  procedure.use(({ ctx, next }) =>
    next({ ctx: { ...ctx, perimeter: buildSecurityPerimeter(ctx) } })
  );

/**
 * Wraps a connector's base `t.procedure` with middleware that names the
 * logger after the full route (e.g. `mysql.accesses.role.list`) so every log
 * line a handler emits is traceable to the call that produced it, and logs
 * invocation/completion of the method itself.
 */
export const withRouteLogging = <
  TRPCInstance extends AnyConnectorTRPCInstance = AnyConnectorTRPCInstance,
>(
  procedure: TRPCInstance["procedure"]
) =>
  procedure.use(async ({ ctx, path, next }) => {
    const logger = ctx.logger.child({ name: path });
    logger.info("connector request received");
    const result = await next({ ctx: { ...ctx, logger } });
    if (result.ok) {
      logger.info({ ok: true }, "connector request completed");
    } else {
      logger.error(
        { ok: false, error: result.error },
        "connector request errored"
      );
    }
    return result;
  });
