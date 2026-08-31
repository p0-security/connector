# @p0security/connector-sdk

Build a **Custom Application connector**: a small service you write and deploy into your own AWS
or GCP account, that lets P0 grant and revoke access to a system P0 has no other integration for.
P0 never reads your target system and never holds a credential to it — everything your connector
does on the target is between your code and your infrastructure.

## What you implement

Six functions — nothing else:

```ts
import type { ConnectorPrimitives } from "@p0security/connector-sdk";

const primitives: ConnectorPrimitives = {
  validation: (context) => ({ user: null /* or a UserNamespaceValidation */ }),
  getUser: async (context, userBody) => {
    /* return an existing user's id, or null */
  },
  createUser: async (context, userBody) => {
    /* provision a user, return its id */
  },
  deleteUser: async (context, userId) => {
    /* clean up, or no-op */
  },
  setPoliciesForUser: async (context, userId, policies) => {
    /* replace, not append */
  },
  list: async (query) => {
    /* the policy catalogue for the request-access picker */
  },
};
```

Every primitive receives `context: { requestId, appId }` and, where relevant, a `userBody:
{ principal }` or `userId: string`. `policies` is `string[]` — P0 never interprets a policy string,
so encode whatever structure you need into it yourself.

**Four invariants P0's own correctness depends on, and P0 cannot verify any of them:**

1. **`getUser` must be injective for each fixed `appId`.** Two different principals must never
   resolve to the same `UserId` — P0 takes a lock per target user, so a collision means one
   requestor's revoke can silently strip or leave another's access.
2. **`setPoliciesForUser` must be a real replace, not an append.** A revoke that leaves policies
   standing is invisible to P0.
3. **Scope every policy operation by `context.appId`.** `setPoliciesForUser` replaces the policy
   set for that _(application, user)_ pair, not for the user globally — the most common mistake,
   because it works perfectly with one Custom Application and breaks silently the moment a tenant
   installs a second one against the same deployment.
4. **Returning `user: null` from `validation` skips namespace checking entirely** — P0 may then
   touch objects it did not create. Only do this if your target genuinely cannot support
   namespacing (see the JSDoc on `validation` for the tradeoff).

None of this is enforced by types or a test suite — hover each field of `ConnectorPrimitives` in
your editor (its JSDoc comes from `@p0security/connector-core`'s generic definition) for the full
detail on that primitive.

### Throwing errors

Throw `ConnectorError` from a primitive when you can classify the failure — it's how the requestor
gets a real message instead of a generic one, and how P0 tells "your connector rejected this" apart
from "your connector broke":

```ts
import { ConnectorError } from "@p0security/connector-sdk";

throw new ConnectorError({
  type: "object_not_found", // one of 8 fixed types; hover ConnectorErrorType for the rest
  message: `No such role: ${roleName}`,
  payload: { roleName },
});
```

A plain `Error` (or anything else) still works — it reaches the requestor as an `unknown`-typed
error with your original message intact, so nothing you throw is ever silently swallowed. But a
classified `ConnectorError` produces a better outcome (e.g. `insufficient_privileges` becomes a
403 the caller can act on, `rate_limited` a 429), so prefer it wherever you can tell which of the
eight types applies.

## Everything else: one function call

`newCustomConnectorRouter` builds the whole connector router — the access procedures, the
(empty) install router, and the version-reporting `metadata` endpoint — from just your primitives.
Beyond your primitives and, optionally, `ConnectorError`, you should not need any other export
from this package for a standard connector:

```ts
import {
  newCustomConnectorRouter,
  runCloudRunConnector, // or: newCloudFunction, for AWS Lambda
} from "@p0security/connector-sdk";

import packageJson from "../package.json" with { type: "json" };

const router = newCustomConnectorRouter({
  primitives,
  connectorVersion: packageJson.version,
});

// GCP Cloud Run:
runCloudRunConnector("my-connector", router);

// AWS Lambda — export this as your handler instead:
// export const handler = newCloudFunction(router);
```

That's the whole `main`. The registry key (`app`) and access key (`access`) your connector is
reached under are fixed by P0 and wired in for you — you never name them yourself.

If you need per-request state in your primitives (e.g. a target-system client built from the
request-scoped logger), pass a factory instead of a plain object:

```ts
newCustomConnectorRouter({
  primitives: (ctx) => makePrimitives(ctx.logger),
  connectorVersion: packageJson.version,
});
```

## Deploying

- **GCP (Cloud Run)**: `runCloudRunConnector` starts an Express server on `$PORT` (default
  `8080`), gated by a bearer-token check against the identity P0 invokes as. Set
  `INVOKER_SA_EMAIL` to the service account P0 impersonates to call your connector — every
  incoming request fails closed (including P0's own install-time reachability check) if it's
  unset. Grant that identity `roles/run.invoker` on the service; P0 needs no other permission.
- **AWS (Lambda)**: `newCloudFunction` returns your handler directly. There is no bearer-token
  check here — a Lambda invoke payload carries no caller identity to check, so the boundary is
  purely `lambda:InvokeFunction` IAM on the role P0 assumes to call you. Grant that role invoke
  access on your function; P0 needs nothing else.
- **Either cloud**: `metadata.get` (mounted for you) must stay side-effect-free — P0 calls it at
  install time to confirm it can reach your connector at all, before anything else is trusted.
  You don't need to do anything for this; just don't build your own procedures that shadow it.
- `LOG_LEVEL` controls the bundled pino logger (default `info`).

## What P0 does not do

P0 proves at install time that it can _invoke_ your connector — nothing more. It does not verify
your connector can reach your target, does not read your target, and does not detect a connector
that reports success without actually granting anything. Test your own `list` and access flow
against your real target before you deploy. See each primitive's JSDoc for what P0 is trusting you
to get right, since nothing else will catch it.

## License

Copyright © 2026-present P0 Security

This library is free software: you may redistribute it and/or modify it under the terms of the GNU
Lesser General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE) and
[LICENSE.GPL](LICENSE.GPL).
