# p0-connector-okta-aws-iam-federation

Okta AWS IAM Federation connector: reads and prepares one Okta AWS Account
Federation app for P0's AWS sign-in.

The connector signs in to Okta as an Okta API service app, with a private key
JWT client assertion. It reads the service app's private key from the
customer's own secret manager on every call, and calls only the org's Okta
domain. Each call from P0 names the Okta `domain`, the AWS app's `appId`, the
service app's `clientId`, and the secret that holds the private key, as
`privateKey`. The secret holds the key as a JWK.

## Service app

An Okta API service app with public key / private key client authentication,
DPoP off, and these scopes:

- `okta.apps.manage`: read the AWS app and its SAML metadata, set
  `joinAllRoles`, and assign users.
- `okta.schemas.manage`: add `managedByP0` to the app user schema.
- `okta.users.read`: find users by email.

## Install validation

`install.validation.get` checks, in this order, that:

1. `secret`: the connector can read the private key from the secret.
2. `token`: Okta gives the service app an access token with every scope.
3. `app`: the app is an active AWS Account Federation app with SAML 2.0.
4. `metadata`: the app's SAML metadata has an entity ID.

It returns the app's `label` and `entityId`. A failed check is thrown with its
name in `payload.step`.

## Install configuration

`install.configuration.set` adds `managedByP0` to the app user schema and sets
`joinAllRoles` on the app. Both writes can run again, and neither is undone
when the integration is removed. A failure reports `payload.step` as
`configure`, or as one of the validation steps above.

## Role access

`accesses.role` is a resource-hierarchy perimeter. Each call's context names
the app, as above.

- The user is an Okta user, found by primary email. P0 creates no Okta user:
  provisioning a user Okta doesn't have fails with `object_not_found`.
- The resource is a `samlRoles` label, and its ID is the label itself.
  Creating or deleting it, and its policies, do nothing.
- Binding adds the label to the user's `samlRoles`, and first assigns the user
  to the app, marked `managedByP0`, if needed.
- Unbinding removes the label, and unassigns the user if P0 assigned them and
  no label is left. A user or label that is already gone is not an error.
- Listing returns nothing.

Binding and unbinding read, change and write the user's `samlRoles`, so P0
must not run two of them at once for the same user.
