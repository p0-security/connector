# p0-connector-pingone-aws-iam-federation

PingOne AWS IAM Federation connector: checks one PingOne SAML app for P0's AWS
sign-in.

The connector signs in to PingOne as a worker app, with its client secret. It
reads the client secret from the customer's own secret manager on every call,
and calls only PingOne in the app's region. Each call from P0 names the
PingOne `region` (`NA`, `EU`, `CA`, `AP` or `AU`), the `environmentId`, the
SAML app's `appId`, the user attribute that holds the user's AWS roles as
`roleAttribute`, the worker app's `clientId`, and the secret that holds its
client secret, as `clientSecret`.

## Worker app

A PingOne worker app with the "Client Credentials" grant type and the "Client
Secret Basic" token endpoint authentication method. It needs roles on the
app's environment that read applications, their attribute mappings, and the
user schema. Reading users works with Identity Data Read Only; the smallest
set of roles for the install check is not tested.

## The SAML app

- Its Subject NameID format is
  `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`.
- It maps `https://aws.amazon.com/SAML/Attributes/Role` to
  `${user.<roleAttribute>}`.
- It maps `https://aws.amazon.com/SAML/Attributes/SourceIdentity` to
  `${user.email}`, with the name format
  `urn:oasis:names:tc:SAML:2.0:attrname-format:uri`.
- The role attribute is a multi-valued text user attribute with no list or
  pattern of allowed values.

## Install validation

`install.validation.get` checks, in this order, that:

1. `secret`: the connector can read the client secret from the secret.
2. `token`: PingOne gives the worker app an access token.
3. `app`: the app is an enabled SAML app with a persistent NameID format.
4. `mappings`: the app has the `Role` and `SourceIdentity` mappings above.
5. `attribute`: the role attribute is multi-valued text with no allowed
   values.
6. `metadata`: the app's SAML metadata has an entity ID.

It returns the app's `name` and `entityId`. A failed check is thrown with its
name in `payload.step`.
