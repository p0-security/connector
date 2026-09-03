# `gcp-cloudrun` — a Custom Application connector on Cloud Run

A complete, deployable [`@p0security/connector-sdk`](../../) connector: all seven actions, wired
into a Cloud Run service and packaged as a container image.

## Layout

| File               | What's in it                                                       |
| ------------------ | ------------------------------------------------------------------ |
| `src/index.ts`     | Entry point: environment guard, then `newCustomAppCloudRunServer`. |
| `src/actions.ts`   | The seven actions, including the two validators that guard writes. |
| `src/catalogue.ts` | The entitlements `list` returns to P0's request-access picker.     |
| `Dockerfile`       | Two-stage build producing the Cloud Run image.                     |

## Environment

| Variable                             | Required | Purpose                                                                                                                        |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `INVOKER_SA_EMAIL`                   | **yes**  | Service account P0 impersonates to call you. Every request must carry a Google-signed ID token whose `email` claim matches it. |
| `PORT`                               | no       | Listen port. Cloud Run injects this; the SDK defaults to `8080`.                                                               |
| `LOG_LEVEL`                          | no       | pino level for the bundled logger. Defaults to `info`.                                                                         |
| `GIT_REF`, `BUILD_DATE`, `WORKSPACE` | no       | Echoed back by `app.metadata.get`. Set them at deploy time so you can tell which build is live.                                |

`src/index.ts` refuses to start when `INVOKER_SA_EMAIL` is unset. The SDK would otherwise start
fine and reject every request — including P0's install-time reachability check — with a `403`
indistinguishable from a genuine auth failure, which is miserable to debug from the outside.

The bearer check is not a substitute for IAM. Deploy the service private
(`--no-allow-unauthenticated`) and grant `roles/run.invoker` to the same account you put in
`INVOKER_SA_EMAIL`: IAM decides who may reach the container, the bearer check decides whose token
the connector will act on.

## What the actions do

P0 drives a grant through the tRPC routes below. `list` runs while a requester browses for
access; the rest run as a grant is provisioned and expired.

| Route                                    | HTTP        | Calls into                                                                   |
| ---------------------------------------- | ----------- | ---------------------------------------------------------------------------- |
| `app.metadata.get`                       | `GET` query | — (version probe)                                                            |
| `app.accesses.access.list`               | `GET` query | `list`                                                                       |
| `app.accesses.access.identifyUser`       | `POST`      | `validatePrincipal`, then `getUser`                                          |
| `app.accesses.access.provisionUser`      | `POST`      | `validatePrincipal`, then `getUser`, then `createUser` if it returned `null` |
| `app.accesses.access.setPoliciesForUser` | `POST`      | `validateUserId`, then `setPoliciesForUser`                                  |
| `app.accesses.access.deleteUser`         | `POST`      | `validateUserId`, then `deleteUser`                                          |

Every route that touches a user runs the matching validator first, and the request fails
without reaching the action if the validator rejects the user — which is why `deleteUser` and
`setPoliciesForUser` in `src/actions.ts` carry no prefix check of their own. `list` is exempt: it
reads the catalogue and touches no user.

`setPoliciesForUser` receives the full set the user should hold afterwards, not a delta — an empty
array revokes everything. Adding to what was already there is the most common way to write a
connector that never revokes access.

## Build and run

```sh
yarn install
yarn run build
docker build --platform linux/amd64 -t p0-custom-app-connector .
```

Pass `--platform linux/amd64` on an Apple-silicon machine, or the revision fails to start with an
exec format error only once it's deployed. `gcloud builds submit` and `gcloud run deploy --source .`
already build amd64 and pick up this `Dockerfile` on their own.

## License

Copyright © 2026-present P0 Security

Distributed under the GNU Lesser General Public License, version 3 or later. See
[LICENSE](../../LICENSE) and [LICENSE.GPL](../../LICENSE.GPL).
