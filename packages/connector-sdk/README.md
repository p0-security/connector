# @p0security/connector-sdk

Build a **Custom Application connector**: a small service you write and deploy into your own AWS
or GCP account, that lets P0 grant and revoke access to a custom application.

## Implementing Actions

The core of the connector is an implementation for five actions that you provide. These actions
are invoked by P0 to manage access grants in your application.

```ts
import type {
  ConnectorContext,
  CustomAppConnectorActions,
} from "@p0security/connector-sdk";

const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  getUser: async (context, userBody) => {
    /* return an existing P0-managed user's id */
  },
  createUser: async (context, userBody) => {
    /* provision a P0-managed user in the custom application, return its id */
  },
  deleteUser: async (context, userId) => {
    /* delete a P0-managed user in the custom application */
  },
  setPoliciesForUser: async (context, userId, policies) => {
    /* replace the policies attached to a P0-managed user in the custom application */
  },
  list: async (query) => {
    /* the policy catalogue for the request-access picker */
  },
});
```

As a best practice, P0 recommends namespacing users in your application where possible so
that it is clear which users managed by P0 and which are not. One potential way to do this
is implementing the `createUser` action to prefix users with `p0_` and then only deleting
users in the `deleteUser` function if that same prefix is present.

```ts
const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  // ...
  deleteUser: async (context, userId) => {
    if (!userId.startsWith("p0_")) {
      throw new ConnectorError({
        type: "validation_error",
        message: `${userId} was not provisioned by P0`,
        payload: { userId },
      });
    }
    await target.deleteUser(userId);
  },
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

import packageJson from "../package.json" with { type: "json" };

export const handler = newCustomAppLambdaHandler({
  actions: newActions,
  connectorVersion: packageJson.version,
});
```

**GCP Cloud Run** — use `newCustomAppCloudRunServer` in your `index.ts` to turn your `actions`
into a Cloud Run service:

```ts
import { newCustomAppCloudRunServer } from "@p0security/connector-sdk";

import packageJson from "../package.json" with { type: "json" };

const run = newCustomAppCloudRunServer({
  actions: newActions,
  connectorVersion: packageJson.version,
});

run();
```

## Deploying

- **GCP (Cloud Run)**: calling the `run()` that `newCustomAppCloudRunServer` returns starts an
  Express server on `$PORT` (default `8080`), gated by a bearer-token check against the identity P0 invokes
  as. Set `INVOKER_SA_EMAIL` to the service account P0 impersonates to call your connector — every
  incoming request fails closed (including P0's own install-time reachability check) if it's unset.
  Grant that identity `roles/run.invoker` on the service.
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
