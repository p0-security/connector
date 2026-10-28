# p0-connector-1password

1Password connector: gives a person a read-only share link to one item in a
1Password vault, for their email only, which expires on 1Password's side.

Ships as both an AWS Lambda container image and a GCP Cloud Run container
image, built from the same workspace.

## How it reaches 1Password

Service accounts use 1Password's end-to-end-encrypted protocol, and share
links are built on the client, so there is no REST API to call. The connector
uses `@1password/sdk`, pinned to an exact version. Its core is a 13 MB
WebAssembly module that it reads from disk as it loads, so:

- the SDK is left out of the bundle (`external` in `esbuild.mjs`) and ships in
  `node_modules` next to it, and
- the connector loads it on first use, not at startup.

P0 installs one 1Password account at a time, with one service account. The
service account gets **Read Items** and **Share Items** on exactly the vaults
people may request items from, and nothing else: the vaults it can see are the
vaults P0 lists. Its token is stored in the
customer's own AWS Secrets Manager or Google Secret Manager. P0 sends a
pointer to it (`tokenSecret`), never the token, and the connector reads it
with its own cloud identity.

The connector signs in once per secret version and keeps the client while the
container is warm. A rotated secret signs in again on its next read.

## What it does

One resource-root access, `share`. The user is the requestor's P0 email.

P0 makes the share link at stage, after approval, through the connector's own
share route. The user primitives change nothing in 1Password:

- `getUser` returns the email without calling 1Password, and never `null`, so
  `createUser` is never reached.
- `setPoliciesForUser` and `deleteUser` are deliberate no-ops. 1Password has
  no call to delete a share link. A 1Password administrator can delete one
  from the item's sharing history.

### Sharing an item

`install.share.create` makes the share link. P0 calls it once per approved
request, at stage. The connector router has no slot for a route of an
integration's own, so it sits in the install router, beside install
validation. It takes `{ vault, tokenSecret, itemId, email, expireAfter, oneTimeOnly }`,
where `expireAfter` is one of 1Password's durations (`OneHour`, `OneDay`,
`SevenDays`, `FourteenDays`, `ThirtyDays`), and runs, in order:

1. The email's domain must be one `DOMAIN_ALLOW_PATTERN` allows, or it
   refuses with `domain_not_allowed`.
2. The account's sharing policy must allow sharing with a person by email
   (`Authenticated` and `Email`), for at least `expireAfter`, or it refuses
   with `sharing_policy`.
3. 1Password must validate the email as the one recipient. A share without
   recipients is a public link, which the connector never makes.
4. It reads the item, only once every check has passed. The SDK returns it
   with its field values, which go to 1Password's `create` call and nowhere
   else.
5. It makes the link, which opens only for that email. With `oneTimeOnly`,
   the account's one-time links setting in P0, it opens once.

It answers `{ link, expiresAt, oneTimeOnly }`. P0 checks `oneTimeOnly` matches
what it asked for, since a connector too old to know the setting would drop it
and make a link that opens again. 1Password doesn't say when a link expires,
so `expiresAt` is an estimate: when the connector asked, plus `expireAfter`.
The link is never logged or put in an error.

A share can't be listed or deleted, so the connector never retries `create`:
a retry would make a second link. A 1Password administrator can delete a
link from the item's sharing history.

### Listings

`list` gets no request context, so each query carries `context: { vault,
tokenSecret }`. Neither query is for one person, so neither runs the
allowed-domain check.

- `vaults` (context `{ tokenSecret }`): the vaults the service account can
  see, each `{ key: <vault id>, value: <title> }`. Only the count is logged.
- `items`: the vault's active items, each `{ key: <item id>, value: <title>,
group: <category> }`, such as `Login`. Never a field's value: the SDK's item
  overview has none. Titles can be sensitive, so only the count is logged.
- `sharing-policy` (with `itemId`): the account's item sharing policy, which
  1Password reads through an item. One answer per field, each `{ key, value }`:
  `maxExpiry` and `defaultExpiry` (such as `SevenDays`), and
  `allowedRecipientTypes` and `allowedTypes`, comma-joined (such as
  `Email,Domain`).

Making a share is not a listing.

### The operations it calls

The connector calls only these SDK operations:

| Operation                         | Why                                                                 |
| --------------------------------- | ------------------------------------------------------------------- |
| `createClient`                    | Sign in with the account's service account token                    |
| `vaults.list`                     | `vaults`, and install: the token sees at least one vault            |
| `items.list`                      | `items`, and install: an item to read the policy through            |
| `items.shares.getAccountPolicy`   | `sharing-policy`, sharing, and install: sharing by email is allowed |
| `items.get`                       | Sharing: the item the link is made from                             |
| `items.shares.validateRecipients` | Sharing: the email as the link's one recipient                      |
| `items.shares.create`             | Sharing: the link                                                   |

It never runs the `op` CLI, and never asks for vault access or group
membership.

## Allowed domains

`DOMAIN_ALLOW_PATTERN` is required. The connector refuses to start without a
pattern that compiles. It's matched against the part of the email after `@`.

The pattern runs **unanchored**, so `acme\.com` also matches
`acme.com.evil.io`. Anchor it: `^acme\.com$`, or `^(acme\.com|acme\.io)$`.
It ignores case, as domain names do.

It's the only limit on who a link goes to. 1Password's sharing policy only
says whether links may go to an email at all: it accepted an address outside
the account's domain when this was checked against a real account (INT-547).
1Password hands the recipient back lowercased, so the share route compares
the email it sent with the one 1Password returns ignoring case.

## Install validation

`install.validation.get` takes `{ tokenSecret }`, for one 1Password account,
and runs these checks in order. A failed check throws a `ConnectorError` whose
`payload.step` names it.

1. `secret`: the connector can read the token.
2. `authenticate`: 1Password accepts it.
3. `vaults`: the service account can see at least one vault.
4. `sharing`: the account's sharing policy allows sharing an item with a
   specific person, by email. 1Password reads the policy through an item, so
   this uses the first active item of the first vault that has one, and is
   skipped with a warning when none has. It can't prove a share would be made: a share can't be
   deleted, so the check makes none.
5. `domains`: the connector's `DOMAIN_ALLOW_PATTERN`.

When every check passes it returns `{ vaultCount, sharingChecked,
allowedDomains }`.

## Errors

The SDK's errors carry only a message from its Rust core, which nothing
promises is free of what the call carried. The connector never repeats it. A
rate limit and an expired token are worded as such; anything else gets the
connector's own message, with the failure's code and status when it has them.

## Copied code

Copied rather than shared, so that adding 1Password changes no other
connector:

- `src/secrets.ts` and `src/allowed-domains.ts`, from `p0-connector-docker`
- `src/refusals.ts`, `src/onepassword/failure.ts` and the install-step
  pattern, from `p0-connector-harbor`
