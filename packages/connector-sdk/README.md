# @p0security/connector-sdk

Build a **custom application connector**: a small service you write and deploy into your own AWS
or GCP account, that lets P0 grant and revoke access to a custom application.

## Implementing Actions

The core of the connector is an implementation for seven actions that you provide. These actions
are invoked by P0 to manage access grants in your application.

```ts
import type {
  ConnectorContext,
  CustomAppConnectorActions,
} from "@p0security/connector-sdk";

const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  validatePrincipal: async (context, principal) => {
    /* whether P0 may act on this principal */
  },
  validateUserId: async (context, userId) => {
    /* whether P0 may act on this user id */
  },
  getUser: async (context, { principal }) => {
    /* return an existing P0-managed user's id */
  },
  createUser: async (context, { principal }) => {
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

## Validating users

Two validation functions are required: `validatePrincipal` and `validateUserId`. The
**principal** is the identity of the requestor in P0. The **user ID** is the identifier
of a user in the application itself. In many cases, the principal can simply be
reused as the user ID in the application.

Some potential implementations, depending on your requirements, include:

- Namespacing P0-managed users. For example, if `john.doe@acme.com` is the principal,
  then creating a user `p0_john_doe` and checking that the user ID is prefixed with `p0_`.
- Domain verification on email addresses. For example, verifying that `john.doe@acme.com`
  has `@acme.com` as a suffix.
- Checking for a tag, group membership, or an organizational unit that a user lives in
  the application.

When implemented, these validation functions can be used to ensure that:

- Users cannot be created in the application that don't follow specific rules or
  conventions
- P0-managed users are easily distinguishable from other users in the application
- Permissions are only modified on P0-managed users in the application
- Only P0-managed users are deleted in the application

While both of these validations are required, you can opt out of user validation by
simply returning `true`:

```ts
const newActions = (ctx: ConnectorContext): CustomAppConnectorActions => ({
  // This application's users are bare email addresses, with nowhere to put a
  // marker distinguishing the ones P0 created.
  validatePrincipal: async () => true,
  validateUserId: async () => true,

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
