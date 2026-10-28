# p0-connector-servicenow-ai

ServiceNow (AI) connector - enables access provisioning/deprovisioning for
ServiceNow roles on per-session agent users.

Each agent session gets one ServiceNow machine user, named `p0-agent-<agent
key>` from the agent key that P0 computes. The connector manages it with the
Table API as the instance's provisioner integration, which needs only
`user_admin`.

- `provisionUser` finds the agent user, or creates it (`identity_type=machine`,
  web service access only).
- `setPoliciesForUser` makes the user hold exactly the given roles, checks that
  ServiceNow kept each role, gets a token for the user with the JWT bearer
  grant, and writes it to the session's token secret.
- `deleteUser` deletes the user, which stops its tokens at once, and deletes
  the token secret.
- `list` (`type: "role"`) returns the roles that are not elevated privilege
  roles.

The connector never grants `admin`, `security_admin`, `user_admin` or other
administrative roles. ServiceNow also refuses `admin` to a `user_admin`
provisioner, but it answers 201 and keeps the row without the role, so the
connector reads the roles back after each change.

## Install secret

The connector reads one GCP Secret Manager secret, named by
`installSecretId`. Its value is a JSON object:

```json
{
  "provisionerClientSecret": "<client secret of the client credential integration>",
  "jwtClientSecret": "<client secret of the JWT bearer integration>",
  "signingKey": "<PEM RSA private key whose certificate the JWT bearer integration trusts>"
}
```

The connector sends the client secrets only to a host that ends in
`.service-now.com`.

## Token

The JWT that the connector signs has `iss` and `aud` set to the JWT bearer
integration's client ID (ServiceNow refuses another `iss`), `sub` set to the
user's `user_name`, and `kid` set to the certificate's key ID in the
integration's verifier map. The token lasts as long as the integration's access
token lifespan (30 minutes by default). Nothing refreshes it.
