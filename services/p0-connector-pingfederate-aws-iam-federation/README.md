# p0-connector-pingfederate-aws-iam-federation

PingFederate AWS IAM Federation connector: checks one PingFederate SP
connection to AWS, and the SCIM inbound provisioning connection that writes
the user's AWS roles.

The connector calls PingFederate's SCIM 2.0 endpoint
(`<pingFederateUrl>/pf-scim/v2`) with HTTP Basic credentials. The credentials
select PingFederate's SCIM IdP connection, which writes to the user store
(Active Directory). The connector reads the password from the customer's own
secret manager on every call. Each call from P0 names:

- `pingFederateUrl`: PingFederate's runtime base URL (`https://`).
- `scimUsername` and `scimPassword`: the SCIM connection's user name, and the
  secret that holds its password.
- `roleAttribute`: the multi-valued attribute in the SCIM connection's custom
  schema (`urn:scim:schemas:extension:custom:2.0`) that holds the user's AWS
  roles.
- `caCertificate` (optional): PEM certificates to trust for PingFederate, for
  a certificate that an internal CA issued.

The connector must run in a network that reaches PingFederate's runtime,
including the `/pf-scim` path.

## PingFederate setup

The SCIM IdP connection needs:

- Read Users mappings for `emails.work.value` (the user's email) and the role
  attribute. PingFederate fills the user's SCIM `id` from `objectGUID`, but
  only when the Read Users LDAP attribute source has no ID. With an ID (as
  the admin API saves it), searches return users with no `id`.
- A Write Users mapping for the role attribute.
- The role attribute in the custom SCIM schema, multi-valued and read-write.

## Install validation

`install.validation.get` checks, in this order, that:

1. `secret`: the connector can read the SCIM password from the secret.
2. `scim`: PingFederate accepts the credentials, and can search users by
   `emails.work.value`.
3. `attribute`: the custom SCIM schema has the role attribute, multi-valued
   and read-write.
4. `metadata`: PingFederate's metadata URL
   `<pingFederateUrl>/pf/federation_metadata.ping?PartnerSpId=urn:amazon:webservices`
   has an entity ID.

It returns the `entityId`. A failed check is thrown with its name in
`payload.step`. Every check only reads; the install doesn't check that
PingFederate's data store account can write the role attribute.
