# `aws-lambda` — a Custom Application connector on AWS Lambda

A complete, deployable [`@p0security/connector-sdk`](../../) connector: all six actions, wired
into an AWS Lambda function via `newCustomAppLambdaHandler`.

## Layout

| File               | What's in it                                                          |
| ------------------ | --------------------------------------------------------------------- |
| `src/index.ts`     | Entry point: `export const handler = newCustomAppLambdaHandler(...)`. |
| `src/actions.ts`   | The six actions, including the validator that guards every write.     |
| `src/catalogue.ts` | The entitlements `list` returns to P0's request-access picker.        |
| `package.sh`       | Builds and zips the function into `connector-lambda.zip`.             |

## Authorization

Unlike the Cloud Run variant, there is no application-level bearer check here (no
`INVOKER_SA_EMAIL` equivalent): AWS IAM is the only gate. P0 calls this function by assuming a
role in your account (set up via the `p0_aws_iam_write` Terraform resource, or the equivalent
console install flow) and invoking it with `lambda:InvokeFunction`. Whoever holds that permission
on this function's ARN can call it — there's no second, in-connector identity check to configure,
because Lambda has no public ingress for someone to reach the function without that IAM grant in
the first place.

## What the actions do

P0 drives a grant through the tRPC routes below, all served through the single Lambda invocation
(there is no HTTP server — `newCustomAppLambdaHandler` wraps the same router the Cloud Run
variant serves over HTTP, but AWS invokes it directly with a synchronous `Invoke` call). `list`
runs while a requester browses for access; the rest run as a grant is provisioned and expired.

| Route                                    | Calls into                                                                  |
| ---------------------------------------- | --------------------------------------------------------------------------- |
| `app.metadata.get`                       | — (version probe)                                                           |
| `app.accesses.access.list`               | `list`                                                                      |
| `app.accesses.access.identifyUser`       | `validateUser`, then `userExists`                                           |
| `app.accesses.access.provisionUser`      | `validateUser`, then `userExists`, then `createUser` if it returned `false` |
| `app.accesses.access.setPoliciesForUser` | `validateUser`, then `setPoliciesForUser`                                   |
| `app.accesses.access.deleteUser`         | `validateUser`, then `deleteUser`                                           |

Every route that touches a user runs `validateUser` first, and the request fails without reaching
the action if the validator rejects the principal. This example admits every principal, so it runs
out of the box; `src/actions.ts` says where a real check — an email domain, a directory lookup, a
group membership test — belongs. `list` is exempt: it reads the catalogue and touches no user.

`setPoliciesForUser` receives the full set the user should hold afterwards, not a delta — an empty
array revokes everything. Adding to what was already there is the most common way to write a
connector that never revokes access.

## Build and package

```sh
./package.sh
```

This installs dependencies, compiles `src/` to `dist/`, then stages `dist/`, a production-only
`node_modules`, and `package.json` at the zip root and writes `connector-lambda.zip`. `dist/`
stays nested rather than flattened — `src/index.ts` locates `package.json` via `../package.json`,
which only resolves correctly with `dist/` one level below the package root, same as during local
development.

Deploy that archive as the function's code (`aws_lambda_function.filename` /
`source_code_hash = filebase64sha256(...)` in Terraform, or the console's "Upload from .zip file"),
with:

- Runtime: `nodejs22.x` (or newer — matches this package's `type: module` + `engines.node`)
- Handler: `dist/index.handler`

## License

Copyright © 2026-present P0 Security

Distributed under the GNU Lesser General Public License, version 3 or later. See
[LICENSE](../../LICENSE) and [LICENSE.GPL](../../LICENSE.GPL).
