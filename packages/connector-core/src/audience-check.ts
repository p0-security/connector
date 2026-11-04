/**
 * The tRPC context key under which `runCloudRunConnector` and
 * `runHttpConnector` record whether they check the token's audience, so
 * `app.metadata.get` can report it.
 *
 * The router is built before the runner reads the environment, and the Lambda
 * and Azure runtimes share it, so the mode can't be baked into the router.
 * Only those two runners set the key; on the other runtimes it's absent and
 * the metadata leaves the field out. A symbol keeps it apart from whatever the
 * connector's own context factory returns, and `Symbol.for` keeps it the same
 * across two copies of this package.
 *
 * Not exported from the package index.
 */
export const AUDIENCE_CHECK_CONTEXT_KEY: unique symbol = Symbol.for(
  "@p0security/connector-core/audienceCheck"
);

/** Reads the audience-check mode the runner put in a request's context. */
export const audienceCheckFromContext = (ctx: unknown): boolean | undefined => {
  if (typeof ctx !== "object" || ctx === null) return undefined;
  const value = (ctx as { [AUDIENCE_CHECK_CONTEXT_KEY]?: unknown })[
    AUDIENCE_CHECK_CONTEXT_KEY
  ];
  return typeof value === "boolean" ? value : undefined;
};
