import type { CloudSqlEngine } from "./definition.ts";

// PostgreSQL identifier limit (NAMEDATALEN - 1).
export const MAX_POSTGRES_DB_USERNAME_LENGTH = 63;

// TODO(mysql): wire up MySQL's 32-char limit.
export const MAX_LIMIT_BY_ENGINE: Partial<Record<CloudSqlEngine, number>> = {
  postgres: MAX_POSTGRES_DB_USERNAME_LENGTH,
};

/**
 * Whether the derived `dbUsername` exceeds the engine's length limit. A long SA
 * name in a long project id can exceed 63 even after stripping
 * `.gserviceaccount.com` (e.g. 30-char SA in a 30-char project -> 65). See
 * https://github.com/hashicorp/terraform-provider-google/issues/15520
 */
export const dbUsernameExceedsLimit = (
  engine: CloudSqlEngine,
  dbUsername: string
): boolean =>
  engine === "postgres" && dbUsername.length > MAX_POSTGRES_DB_USERNAME_LENGTH;

/**
 * Derives the CloudSQL DB username from the verified IAM email. Postgres SAs
 * strip the `.gserviceaccount.com` suffix; everything else uses the email.
 */
export const toDbUsername = (engine: CloudSqlEngine, email: string): string =>
  engine === "postgres" && email.endsWith(".gserviceaccount.com")
    ? email.replace(/\.gserviceaccount\.com$/, "")
    : email;
