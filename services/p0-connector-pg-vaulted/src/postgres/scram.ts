import { createHash, createHmac, pbkdf2Sync } from "node:crypto";

const ITERATIONS = 4096;
const KEY_BYTES = 32;

/** The length of a verifier's salt, which is PostgreSQL's own. */
export const SALT_BYTES = 16;

const hmac = (key: Buffer, text: string) =>
  createHmac("sha256", key).update(text).digest();

/**
 * The SCRAM-SHA-256 verifier of `password`, in the form PostgreSQL keeps in
 * `pg_authid`: `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`
 * (RFC 5803). PostgreSQL stores a `PASSWORD` of this form as it is, so the
 * password never reaches the server, its logs or `pg_stat_statements`.
 *
 * The password is not normalized with SASLprep, which leaves ASCII as it
 * is. The connector's passwords are ASCII.
 */
export const scramVerifier = (password: string, salt: Buffer) => {
  const salted = pbkdf2Sync(password, salt, ITERATIONS, KEY_BYTES, "sha256");
  const storedKey = createHash("sha256")
    .update(hmac(salted, "Client Key"))
    .digest();
  const serverKey = hmac(salted, "Server Key");
  return `SCRAM-SHA-256$${ITERATIONS}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
};
