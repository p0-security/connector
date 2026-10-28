# p0-connector-tableau-ai

Tableau (Agentic) connector - enables access provisioning/deprovisioning for
Tableau Cloud projects.

Each secret has its own agent user in the site. The control plane keeps one
secret for each requester and site, and merges the projects of all of that
requester's open grants into its policy. The secret's value is a REST session
token for the agent user. The agent user gets read or write permissions on
each project in the policy, and on the project's content
through its default permissions. Only projects whose permissions are locked to
the project can be granted, because only those apply their default
permissions to all of their content.

A policy change updates the agent user's permissions in place and stores a new
session token. When no grants remain, the connector removes the agent user, which
ends its open sessions, and deletes the secret.

A consumer sends the token as `X-Tableau-Auth: <token>` to the Tableau REST API.

## Agent users

An agent user's name is the install's agent mailbox, plus-addressed with a hash
of its secret, e.g. `p0-agents+p0-0123456789abcdef@example.com`.
Tableau Cloud emails an invitation to each new user, so the mailbox gets one
email per agent user. Each agent user takes a seat while any of its grants is open.

| Highest level | Site role            |
| ------------- | -------------------- |
| `read`        | `Viewer`             |
| `write`       | `ExplorerCanPublish` |

## Admin connected app

The connector reads a direct-trust connected app from the secret named by
`adminAppSecretId`. Its value is JSON:

```json
{ "clientId": "...", "secretId": "...", "secret": "..." }
```

The connector signs in with this app as `adminUser`, a site administrator, to
add, change and remove agent users and their project permissions. It also
signs in as each agent user to make its session token.

## Limitations

- A Tableau Cloud REST session token expires after 120 minutes. The connector
  makes a new one only when a grant's policies change.

## Creating local builds

Build and publish the images as described in the
[Datadog connector README](../p0-connector-datadog-ai/README.md#creating-local-builds),
with `WORKSPACE=@p0security/p0-connector-tableau-ai` and image names
`p0-connector-tableau-ai-aws` (AWS Lambda) and `p0-connector-tableau-ai-gcloud`
(GCP Cloud Run).
