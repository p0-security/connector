# @p0security/connector-sdk

Build a **custom application connector**: a small service you write and deploy into your own AWS
or GCP account, or onto any other host, that lets P0 grant and revoke access to a custom
application.

## Implementing Actions

The core of the connector is an implementation for six actions that you provide. These actions
are invoked by P0 to manage access grants in your application.

```ts
import type {
  ConnectorContext,
  CustomAppConnectorActions,
} from "@p0security/connector-sdk";

const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  validateUser: async (context, user) => {
    /* whether P0 may act on this user */
  },
  userExists: async (context, user) => {
    /* whether this user already exists in the custom application */
  },
  createUser: async (context, user) => {
    /* provision a P0-managed user in the custom application */
  },
  deleteUser: async (context, user) => {
    /* delete a P0-managed user in the custom application */
  },
  setPoliciesForUser: async (context, user, policies) => {
    /* replace the policies attached to a P0-managed user in the custom application */
  },
  list: async (query) => {
    /* the policy catalogue for the request-access picker */
  },
});
```

## Validating users

One validation function is required: `validateUser`. The SDK calls it before every other action
that touches a user — `userExists`, `createUser`, `deleteUser`, and `setPoliciesForUser` — and
abandons the request if it returns `false`.

Some potential implementations, depending on your requirements, include:

- Domain verification on the principal. For example, verifying that `john.doe@acme.com` has
  `@acme.com` as a suffix.
- Checking for a tag, group membership, or an organizational unit that a principal lives in.
- A directory lookup, to confirm the principal is someone your organization still employs.

While this validation is required, you can opt out of user validation by simply returning `true`:

```ts
const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  // This application's users are bare email addresses, with nowhere to put a
  // marker distinguishing the ones P0 created.
  validateUser: async () => true,

  // ...
});
```

## Throwing errors

Throw `ConnectorError` from an action to indicate to P0 what kind of error occurred:

```ts
import { ConnectorError } from "@p0security/connector-sdk";

throw new ConnectorError({
  type: "object_not_found",
  message: `No such role: ${roleName}`,
  payload: { roleName },
});
```

## Wiring a router to a runtime

**AWS Lambda** — use `newCustomAppLambdaHandler` in your `index.ts` to turn your `actions`
into an AWS Lambda handler:

```ts
import { newCustomAppLambdaHandler } from "@p0security/connector-sdk";

export const handler = newCustomAppLambdaHandler({ actions: newActions });
```

**GCP Cloud Run** — use `newCustomAppCloudRunServer` in your `index.ts` to turn your `actions`
into a Cloud Run service:

```ts
import { newCustomAppCloudRunServer } from "@p0security/connector-sdk";

const run = newCustomAppCloudRunServer({ actions: newActions });

run();
```

**Any other host**: use `newCustomAppHttpServer` the same way. It serves the same routes as
the Cloud Run server, and by default also checks the token's audience:

```ts
import { newCustomAppHttpServer } from "@p0security/connector-sdk";

const run = newCustomAppHttpServer({ actions: newActions });

run();
```

P0 reads your connector's version from its `metadata.get` route. The connector reports the
version of `@p0security/connector-sdk` it was built with, so upgrading the SDK upgrades the
connector. Earlier releases took a `connectorVersion` argument. It is now ignored, and you can
delete it.

## Deploying

- **GCP (Cloud Run)**: calling the `run()` that `newCustomAppCloudRunServer` returns starts an
  Express server on `$PORT` (default `8080`), gated by a bearer-token check on the Google ID token P0
  sends. Set `INVOKER_SA_EMAIL` to the service account P0 impersonates to call your connector; the
  token's `email` claim must match it, and `run()` throws before binding a port if it's unset or
  empty. The connector doesn't check the token's audience, so deploy the service private and grant
  `INVOKER_SA_EMAIL` `roles/run.invoker` on it: Cloud Run's invoker check is what turns away a
  token minted for another service. The one exception is `GET /health`, which answers `200`
  without a token so a load balancer can health-check the container. It returns only the module
  name and reaches none of your actions.
- **Any other host**: the `run()` that `newCustomAppHttpServer` returns starts the same
  server, with the same `INVOKER_SA_EMAIL` check and `GET /health` route. It speaks plain HTTP on
  `$PORT`, so put it behind a load balancer, ingress or proxy that terminates TLS. P0 sends a
  bearer token with every request. `CONNECTOR_AUDIENCE` is required: nothing in front of the service
  checks the audience, so the connector rejects any token whose `aud` claim differs from it. Set it
  to the exact string P0 shows when you register the connector. It names both your connector and
  your P0 organization, so copy it rather than building it. `run()` throws before binding a port if
  it's unset, empty, or has leading or trailing whitespace.
- **Behind a trusted proxy**: if an API gateway in front of the connector authenticates P0 and
  replaces the `Authorization` header with its own credential, set `CONNECTOR_AUTH=trusted-proxy`.
  P0 then also sends its own short-lived identity token as `X-P0-Authorization: Bearer <token>`,
  and the connector checks that instead of `Authorization`, which it ignores. Set
  `CONNECTOR_AUDIENCE` as above, and `CONNECTOR_IDENTITY_JWKS` to the JSON Web Key Set P0 gives
  you: one or two RSA keys of at least 2048 bits, each with its own `kid` and `alg` `RS256`. Two
  keys let P0 rotate its key without downtime. The token must be `RS256`, signed with the key its
  `kid` names, and have `iss` `p0`, `aud` exactly `CONNECTOR_AUDIENCE` and a `sub`. It must not be
  expired, must not have an `iat` in the future, and must live at most 15 minutes (`exp` minus
  `iat`); the connector allows 60 seconds of clock skew, so keep the host's clock in sync. Every
  path except `GET /health` needs the token, so a request without a valid one gets a `403`, on an
  unknown path too. A JSON body is parsed before the token is checked, though, so one that isn't
  valid JSON gets a `400`, and one over 5 MB a `413`, whatever the token. The `403` body is only
  `{"error": {"message": "Unauthorized", "publicMessage": "P0 could not properly identify you."}}`;
  the log says which check failed, never the token. The connector fetches nothing to check the
  token, and `INVOKER_SA_EMAIL` isn't needed. `run()` throws before binding a port if either
  variable is missing or invalid. The server listens on `127.0.0.1` by default, `/health` included:
  point the proxy at `127.0.0.1`, not `localhost`, which may resolve to `::1`. Set
  `CONNECTOR_BIND_ADDRESS` to an IP address to listen elsewhere; an address other than `127.x.x.x`
  or `::1` logs a warning at startup.
- For `newCustomAppHttpServer`, `CONNECTOR_AUTH` defaults to `google-id-token`, the check described
  under **Any other host**. Any value other than `google-id-token` or `trusted-proxy` makes `run()`
  throw. `CONNECTOR_BIND_ADDRESS` works in both modes, and `run()` throws if it's set to anything
  but an IP address, such as a host name; `google-id-token` listens on every interface by default.
- **AWS (Lambda)**: `newCustomAppLambdaHandler` returns your handler directly. There is no
  bearer-token check here — a Lambda invoke payload carries no caller identity to check, so the
  boundary is purely `lambda:InvokeFunction` IAM on the role P0 assumes to call you. Grant that role
  invoke access on your function.
- `LOG_LEVEL` controls the bundled pino logger (default `info`).

## License

Copyright © 2026-present P0 Security

This library is free software: you may redistribute it and/or modify it under the terms of the GNU
Lesser General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[LICENSE.GPL](LICENSE.GPL).
