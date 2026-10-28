# p0-connector-tailscale

P0's Tailscale connector. It runs in the customer's AWS Lambda or GCP Cloud
Run, calls only the Tailscale API (`https://api.tailscale.com`), and grants
network access on a tailnet just in time.

## What it does

The customer's policy file, edited however they like (the admin console,
git, Terraform), gates grants on P0 postures. P0 sets a custom device
attribute on the requestor's device for the grant's duration, and deletes
it at revoke. P0 never writes the policy file.

Custom device attributes need a **Premium or Enterprise** Tailscale plan.

### Install validation

`install.validation.get` runs these checks in order. A failure throws a
`ConnectorError` with the check's name in `payload.step`:

1. `credential`: the OAuth client's secret reads from the customer's secret
   manager, or the connector's cloud identity mints a token.
2. `authenticate`: Tailscale exchanges the credential for an access token.
3. `scopes`: each endpoint P0 needs answers. A missing scope is named. An
   OAuth client's write scope is proved by exchanging for it, which writes
   nothing. A federated identity's are compared with the scopes Tailscale
   says its token carries (a write scope covers its `:read`). When
   Tailscale names none, the check fails, since nothing else shows the
   token can't write the policy file. A credential that carries
   `policy_file` or `all` is refused, since either can write the policy
   file. When Tailscale names none of an OAuth client's scopes, an exchange
   for `policy_file` shows whether the client holds it.
4. `posture`: sets `custom:p0_install_check` on the tailnet's first
   untagged device of its own (by node id) with a one-minute expiry, then
   removes it. A request can't name `posture:p0_install_check`, so the
   check opens no grant P0 approved. A refusal means the plan can't hold
   custom attributes (Premium or Enterprise only) or the credential can't
   set them. It's the one check that writes, so `skipPostureWrite: true`
   skips it. The app sets that once the tailnet is installed.
5. `discovery`: counts the `posture:p0_*` postures in the policy file.

A validation that passes also answers the tailnet's DNS name, such as
`tail1234.ts.net`, for the app to show next to the Tailnet ID. It's the
domain of the first own device's MagicDNS name (a shared-in device has
another tailnet's), since no endpoint a tailnet's credential can read
answers it. A tailnet with no device of its own answers none.

### `posture`

The one access, a resource-root access. The customer's policy file defines
each P0 posture, and gates grants on it:

```hujson
"postures": {
  "posture:p0_prod_db": {"assertions": ["custom:p0_prod_db == true"]},
},
"grants": [
  {"src": ["autogroup:member"], "dst": ["tag:prod-db"], "ip": ["tcp:5432"],
   "srcPosture": ["posture:p0_prod_db"]},
],
```

The user is the device the requestor chose (its node id). The policies are
the union of every open request on that device, `{ posture, expiresAt }`
each. `setPoliciesForUser` makes the device's `custom:p0_*` attributes
exactly that, in one `PATCH /tailnet/{tailnet}/device-attributes`: each key
`true` until the latest end among the requests that carry it, every other
`custom:p0_*` key deleted, nothing outside `custom:p0_` touched. A revoke
deletes the key itself; Tailscale's expiry, which it applies within a few
minutes, is the safety net.

A grant is refused for a device that isn't the requestor's, for a device
shared in from another tailnet, and for a tagged device, whose user is
whoever registered it. A revoke checks none of these. A device that's gone
is a revoke with nothing to do, but only once the tailnet's device list
answers without it: Tailscale answers a device read with 404 when the
token lacks a scope too, so any other 404 fails the revoke. The write
token is `devices:posture_attributes` alone, so no call can write the
policy file.

### Listings

The posture access's `list` answers a query that carries the tailnet's
credentials, with a read-only token:

| `type`        | One entry per                   | `key`   | `value`        | `group`          |
| ------------- | ------------------------------- | ------- | -------------- | ---------------- |
| `own-devices` | the requestor's untagged device | node id | name           |                  |
| `postures`    | `posture:p0_*` posture          | posture | its assertions | the key it reads |

`own-devices` leaves out devices shared in from another tailnet.

### Posture check

`install.destination.check` confirms the requested `posture:p0_*` posture
is in the policy file and checks `custom:p0_<name> == true`. For the
approver, it answers what the posture unlocks: the `grants` entries whose
`srcPosture` names it (or the file's `defaultSrcPosture`), legacy `acls`
entries that do, in the grant shape (`dst` hosts, `ip` ports), and `ssh`
rules, with capabilities by name only. The app calls it when a request is
made.

### Errors

| Tailscale                               | P0 sees                   |
| --------------------------------------- | ------------------------- |
| the credential refused, or a 401 or 403 | `insufficient_privileges` |
| 404 to a token known to lack the scope  | `insufficient_privileges` |
| any other 404                           | `object_not_found`        |
| 429                                     | `rate_limited`            |
| 5xx, or no answer                       | `upstream_unavailable`    |
| 400, 402 or 409                         | `validation_error`        |

A 402 is the tailnet's plan: custom device attributes need a Premium or
Enterprise plan. A grant or revoke whose attribute write Tailscale answers
with 400, 402 or 403, for a device that's still on the tailnet, is
`insufficient_privileges`, and its message names the plan and
`devices:posture_attributes`.

Messages are built from facts. Only a refusal quotes Tailscale's own reason,
with any secret cut out. No secret, identity token or access token reaches a
log line, an error or a response.

## Configuration

A tailnet is `{ tailnet, credential }`:

- `tailnet`: the **Tailnet ID** from Settings > General, such as
  `T1234CNTRL`. A tailnet created before October 2025 also answers to its
  legacy ID (`example.com`). The DNS name (`tail1234.ts.net`) is refused: the
  API doesn't take it.
- `credential`, one of:
  - `{ kind: "federated", clientId }`: a federated identity whose issuer is
    AWS outbound identity federation or Google, with the connector's role or
    service account as its subject. The connector asks for Tailscale's
    default audience, `api.tailscale.com/<clientId>`. On AWS the role needs
    `sts:GetWebIdentityToken` for that audience, with `sts:DurationSeconds`
    of at least 300.
  - `{ kind: "vault", clientId, secret }`: an OAuth client, whose secret is
    at `secret`, a pointer into AWS Secrets Manager
    (`{ manager: "aws", secretId, region }`) or Google Secret Manager
    (`{ manager: "gcp", secretId, projectId }`). The connector's identity
    needs read access to it.

### Scopes

The credential holds these, and not `policy_file` or `all`:

- `policy_file:read`
- `users:read`
- `devices:core:read`
- `devices:posture_attributes`
- `devices:routes:read`
- `services:read`

An OAuth client's tokens are narrowed per call: read-only scopes for
discovery, checks and listings, and `devices:posture_attributes` alone for
a grant or revoke. A federated identity's token carries every scope
configured on the identity, because Tailscale's token exchange takes no
scope.

## Spec test

[`scripts/admin-test.sh`](scripts/admin-test.sh) is the spec test for
INT-666: one check per Tailscale behaviour this connector relies on (token
flows and scopes, error codes, reading the policy file, postures and device
attributes, devices, services, rate limits, revoke timing), each by its
inventory number, run against a throwaway lab tailnet on a Premium trial.
Each check records PASS, FAIL, SKIP (its setup is missing) or HUMAN (you did
something and answered).

Run `--setup` first to fill in its env file (`.env` in the folder you run
it from). Setup walks you through creating two OAuth clients in the admin
console: the connector's, with exactly the scopes above, and an admin
client, the test's own, which writes test postures and posture-gated grants
into the lab policy file. It mints a token, and finds the Tailnet ID, your
login, devices A and B, and any subnet router and service through the API.
It asks for anything the API can't tell it, offers the optional extras, and
ends with a table of what's set and which checks SKIP.
[`scripts/admin-test.env.example`](scripts/admin-test.env.example) lists
every value. Then run the test on device A, signed in as the requestor:

```bash
services/p0-connector-tailscale/scripts/admin-test.sh --setup    # fill in .env
services/p0-connector-tailscale/scripts/admin-test.sh            # every check
services/p0-connector-tailscale/scripts/admin-test.sh --area posture
services/p0-connector-tailscale/scripts/admin-test.sh --only A48,A60
services/p0-connector-tailscale/scripts/admin-test.sh --list     # what it checks
services/p0-connector-tailscale/scripts/admin-test.sh --dry-run  # print the calls only
```

It needs `curl`, `jq` and `perl`, and `aws` or `gcloud` for the federated
checks, which sign in and mint the identity tokens themselves. It runs only
when `TAILNET` equals the env file's `LAB_TAILNET` and you type the ID again.
Secrets are read hidden, never written, and cut from every logged body.
Everything it adds is named after the run (`posture:p0_spec<run>`,
`custom:p0_spec<run>`). Each write is undone after its check and again on
any exit, Ctrl-C included: the policy file is
restored with `If-Match` from a saved copy, and never over someone else's
change. It writes `spec-results-<timestamp>.md` next to the env file, with
the INT-666 items first, ready to paste into INT-666.

## Creating local builds

Both images pull P0's base images from a private GCP Artifact Registry, so log
in and register gcloud as a Docker credential helper for that host first. This
is required for the AWS Lambda image too:

```bash
gcloud auth configure-docker us-west1-docker.pkg.dev
```

Then run these from the repository root:

### AWS Lambda

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/lambda/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-tailscale \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-tailscale:dev .
```

### GCP Cloud Run

```bash
docker build \
  --platform linux/amd64 \
  -f ./docker/connector/cloud-run/Dockerfile \
  --build-arg WORKSPACE=@p0security/p0-connector-tailscale \
  --build-arg GIT_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t p0-connector-tailscale-gcloud:dev .
```

This will set your locally-built images to have the tag `dev`. To publish and
deploy one, follow the steps in
[the Docker Hub connector's README](../p0-connector-docker/README.md#publishing-local-builds),
with `tailscale` in place of `docker`.
