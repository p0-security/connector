import type { AnyRouter } from "@trpc/server";
import {
  type CreateExpressContextOptions,
  createExpressMiddleware,
} from "@trpc/server/adapters/express";
import { type RequestHandler, Router } from "express";
import { OAuth2Client } from "google-auth-library";

import { AUDIENCE_CHECK_CONTEXT_KEY } from "../audience-check.ts";
import { bearerAuthzMiddleware, runExpressApp } from "../http/index.ts";
import { createLogger } from "../logger.ts";

/**
 * Whether the Cloud Run runner compares the token's `aud` claim itself.
 *
 * - `"required"` (the default): `CONNECTOR_AUDIENCE` must be set, and the
 *   token's `aud` must equal it exactly.
 * - `"cloud-run-iam"`: skip the comparison and rely on Cloud Run IAM, which
 *   turns away a token minted for another service. Only safe on a private
 *   Cloud Run service. The runner refuses to start when `K_SERVICE` is unset.
 *
 * `CONNECTOR_AUDIENCE`, when set, is checked in either mode, so a deployment
 * can turn the check on without a rebuild but never off.
 */
export type AudienceCheck = "cloud-run-iam" | "required";

export type CloudRunConnectorOptions = {
  /** Defaults to `"required"`. */
  audienceCheck?: AudienceCheck;
};

const logger = createLogger({ module: "cloud-run-connector" });

/**
 * Decides, at startup, which audience the token must carry. Returns
 * `undefined` when the comparison is off. Throws on a configuration that
 * can't be served safely.
 */
const audienceFromEnv = (mode: AudienceCheck): string | undefined => {
  const audience = process.env.CONNECTOR_AUDIENCE;

  if (audience !== undefined) {
    // google-auth-library compares the audience whenever one is passed, so an
    // empty string would reject every token. Surrounding whitespace (say, a
    // trailing newline from a secret) would do the same. Refuse it rather than
    // trim it, since the value must match what P0 mints.
    if (!audience) {
      throw new Error("Connector audience is not set or present");
    }
    if (audience !== audience.trim()) {
      throw new Error("Connector audience has leading or trailing whitespace");
    }
    return audience;
  }

  if (mode === "required") {
    throw new Error("Connector audience is not set or present");
  }

  // `K_SERVICE` doesn't prove the service is private (Knative sets it too), but
  // its absence proves this isn't Cloud Run.
  if (!process.env.K_SERVICE) {
    throw new Error(
      'Audience check "cloud-run-iam" is only allowed on Cloud Run, and K_SERVICE is not set. Set CONNECTOR_AUDIENCE instead'
    );
  }

  logger.warn(
    "The token audience check is off. Cloud Run IAM is the only audience check, so the service must stay private"
  );
  return undefined;
};

const verifyToken = (mode: AudienceCheck) => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  const audience = audienceFromEnv(mode);
  const verify = async (token: string) => {
    // Without an audience, google-auth-library still checks the signature,
    // issuer and expiry; only the `aud` comparison is skipped.
    const ticket = await client.verifyIdToken(
      audience === undefined ? { idToken: token } : { idToken: token, audience }
    );
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return false;
    }
    const { email } = payload;
    return invokerSAEmail.toLocaleLowerCase() === email.toLowerCase();
  };
  return { verify, audienceCheck: audience !== undefined };
};

/**
 * Creates a Cloud Run service that exposes a tRPC router over Express at
 * `/trpc`, gated by bearer-token auth.
 *
 * Requests must carry a Google-signed ID token whose `email` claim is
 * `$INVOKER_SA_EMAIL` and, by default, whose `aud` claim is exactly
 * `$CONNECTOR_AUDIENCE`. Pass `{ audienceCheck: "cloud-run-iam" }` to skip the
 * `aud` comparison on a private Cloud Run service; see {@link AudienceCheck}.
 * `app.metadata.get` reports which mode is on as `audienceCheck`.
 *
 * Throws before binding a port if `INVOKER_SA_EMAIL` is unset or empty, if
 * `CONNECTOR_AUDIENCE` is empty or has leading or trailing whitespace, or if
 * the audience is required and unset.
 *
 * The context each procedure receives is a shallow copy of what
 * `createContext` returns (an empty object without one), with the audience
 * mode added under a private key.
 *
 * `GET /health` is the one route served without a token, for load balancer
 * health checks. It returns `{ module: moduleName }`.
 * @summary Creates a Cloud Run service that exposes a tRPC router over Express.
 * @category Cloud Functions
 *
 * @param moduleName Name reported by `/health` and used in logs.
 * @param router The tRPC router to mount.
 * @param createContext Optional context factory; receives the Express adapter's options.
 * @param options See {@link CloudRunConnectorOptions}.
 */
export const runCloudRunConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext?: (opts: CreateExpressContextOptions) => Promise<T>,
  options: CloudRunConnectorOptions = {}
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const { verify, audienceCheck } = verifyToken(
    options.audienceCheck ?? "required"
  );

  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      // Hand the mode to `app.metadata.get` through the context, since the
      // router is built before this runs.
      createContext: async (opts: CreateExpressContextOptions) =>
        Object.assign({}, await createContext?.(opts), {
          [AUDIENCE_CHECK_CONTEXT_KEY]: audienceCheck,
        }),
    })
  );

  const middlewares: RequestHandler[] = [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
