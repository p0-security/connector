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
 * The one value of `CONNECTOR_AUDIENCE_CHECK` the runner accepts. It turns the
 * `aud` comparison off when `CONNECTOR_AUDIENCE` is unset, leaving Cloud Run
 * IAM as the only audience check.
 */
const CLOUD_RUN_IAM = "cloud-run-iam";

const logger = createLogger({ module: "cloud-run-connector" });

/**
 * Decides from the environment which audience, if any, the token must carry.
 * Returns `undefined` when the check is off.
 *
 * - `CONNECTOR_AUDIENCE` set: check against it, and ignore the opt-out.
 * - Unset, `CONNECTOR_AUDIENCE_CHECK=cloud-run-iam` and `K_SERVICE` set: skip
 *   the `aud` comparison and rely on Cloud Run IAM.
 * - Anything else: throw.
 *
 * `K_SERVICE` on its own never turns the check off: Knative sets it too, and
 * anyone can set it by hand.
 */
const audienceFromEnv = (): string | undefined => {
  const audience = process.env.CONNECTOR_AUDIENCE;
  const audienceCheck = process.env.CONNECTOR_AUDIENCE_CHECK;

  if (audienceCheck !== undefined && audienceCheck !== CLOUD_RUN_IAM) {
    throw new Error(
      `CONNECTOR_AUDIENCE_CHECK must be unset or "${CLOUD_RUN_IAM}", not ${JSON.stringify(audienceCheck)}`
    );
  }

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
    if (audienceCheck !== undefined) {
      logger.warn(
        "Both CONNECTOR_AUDIENCE and CONNECTOR_AUDIENCE_CHECK are set. Ignoring CONNECTOR_AUDIENCE_CHECK and checking the token's audience against CONNECTOR_AUDIENCE"
      );
    }
    return audience;
  }

  if (audienceCheck === undefined) {
    throw new Error(
      `Connector audience is not set or present. Set CONNECTOR_AUDIENCE, or on a private Cloud Run service set CONNECTOR_AUDIENCE_CHECK=${CLOUD_RUN_IAM}`
    );
  }

  if (!process.env.K_SERVICE) {
    throw new Error(
      `CONNECTOR_AUDIENCE_CHECK=${CLOUD_RUN_IAM} is only allowed on Cloud Run, and K_SERVICE is not set. Set CONNECTOR_AUDIENCE instead`
    );
  }

  logger.warn(
    `The token audience check is off (CONNECTOR_AUDIENCE_CHECK=${CLOUD_RUN_IAM}). Cloud Run IAM is the only audience check, so the service must stay private`
  );
  return undefined;
};

const verifyToken = () => {
  const client = new OAuth2Client();
  const invokerSAEmail = process.env.INVOKER_SA_EMAIL ?? "";
  if (!invokerSAEmail) {
    throw new Error("Invoker service account email is not set or present");
  }
  const audience = audienceFromEnv();
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
 * `$INVOKER_SA_EMAIL` and whose `aud` claim is exactly `$CONNECTOR_AUDIENCE`.
 *
 * On a private Cloud Run service you can set
 * `CONNECTOR_AUDIENCE_CHECK=cloud-run-iam` instead of `CONNECTOR_AUDIENCE`.
 * The connector then skips the `aud` comparison and relies on Cloud Run IAM to
 * turn away a token minted for another service, so the service has to stay
 * private. The opt-out is honoured only when `K_SERVICE` is set, and is
 * ignored, with a warning, when `CONNECTOR_AUDIENCE` is also set.
 * `app.metadata.get` reports which mode is on as `audienceCheck`.
 *
 * Throws before binding a port if `INVOKER_SA_EMAIL` is unset or empty, if
 * `CONNECTOR_AUDIENCE` is empty or has leading or trailing whitespace, if
 * `CONNECTOR_AUDIENCE_CHECK` has any other value, or if neither the audience
 * nor a usable opt-out is set.
 *
 * `GET /health` is the one route served without a token, for load balancer
 * health checks. It returns `{ module: moduleName }`.
 * @summary Creates a Cloud Run service that exposes a tRPC router over Express.
 * @category Cloud Functions
 *
 * @param moduleName Name reported by `/health` and used in logs.
 * @param router The tRPC router to mount.
 * @param createContext Optional context factory; receives the Express adapter's options.
 */
export const runCloudRunConnector = <T>(
  moduleName: string,
  router: AnyRouter,
  createContext?: (opts: CreateExpressContextOptions) => Promise<T>
) => {
  // Read the environment before serving, so a misconfigured connector fails to
  // start rather than answering every request with a 403.
  const { verify, audienceCheck } = verifyToken();

  const trpcRouter = Router();
  trpcRouter.use(
    createExpressMiddleware({
      router,
      // Hand the mode to `app.metadata.get` through the context, since the
      // router is built before this reads the environment.
      createContext: async (opts: CreateExpressContextOptions) =>
        Object.assign({}, await createContext?.(opts), {
          [AUDIENCE_CHECK_CONTEXT_KEY]: audienceCheck,
        }),
    })
  );

  const middlewares: RequestHandler[] = [bearerAuthzMiddleware(verify)];

  return runExpressApp(moduleName, { "/trpc": trpcRouter }, middlewares);
};
