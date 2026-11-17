# p0-connector-pingfederate-aws-iam-federation

PingFederate AWS IAM Federation connector: checks one PingFederate SP
connection to AWS, and the LDAP user store it reads the user's AWS roles from.

The connector binds to the user store over LDAPS as a bind account, with its
password. It reads the password from the customer's own secret manager on
every call. Each call from P0 names:

- `pingFederateUrl`: PingFederate's runtime base URL (`https://`).
- `directoryUrl`: the user store's `ldaps://` URL. Active Directory, OpenLDAP
  and PingDirectory work through the same LDAP operations.
- `bindDn` and `bindPassword`: the bind account, and the secret that holds its
  password.
- `baseDn`: the entry under which the connector finds users.
- `roleAttribute`: the multi-valued attribute that holds the user's AWS roles.
- `caCertificate` (optional): PEM certificates to trust for the user store and
  for PingFederate, for a certificate that an internal CA issued.

The connector must run in a network that reaches the user store and
PingFederate.

## Install validation

`install.validation.get` checks, in this order, that:

1. `secret`: the connector can read the bind password from the secret.
2. `bind`: the bind account can bind to the user store over LDAPS.
3. `baseDn`: the base DN is an entry.
4. `attribute`: the user store's schema has the role attribute, and it is not
   single-valued.
5. `metadata`: PingFederate's metadata URL
   `<pingFederateUrl>/pf/federation_metadata.ping?PartnerSpId=urn:amazon:webservices`
   has an entity ID.

It returns the `entityId`. A failed check is thrown with its name in
`payload.step`. Every check only reads; the install doesn't check that the
bind account can write the role attribute.
