import { describe, expect, it } from "vitest";

import {
  MAX_POSTGRES_DB_USERNAME_LENGTH,
  dbUsernameExceedsLimit,
  toDbUsername,
} from "../cloudsql-user.ts";

describe("toDbUsername", () => {
  it("strips the .gserviceaccount.com suffix for a Postgres service account", () => {
    // The SQL Admin API does NOT truncate this, and the full email exceeds the
    // username length limit, so the connector must strip it itself.
    expect(
      toDbUsername("postgres", "sa-name@project-id.iam.gserviceaccount.com")
    ).toBe("sa-name@project-id.iam");
  });

  it("uses the full email for a Postgres user", () => {
    expect(toDbUsername("postgres", "test-user@example.com")).toBe(
      "test-user@example.com"
    );
  });

  it("uses the full email for a MySQL user (Cloud SQL truncates @domain on storage)", () => {
    expect(toDbUsername("mysql", "example-user@example.com")).toBe(
      "example-user@example.com"
    );
  });

  it("uses the full email for a MySQL service account", () => {
    // Unlike Postgres, MySQL keeps the suffix on submit; it strips @domain
    // internally when storing.
    expect(
      toDbUsername("mysql", "sa-name@project-id.iam.gserviceaccount.com")
    ).toBe("sa-name@project-id.iam.gserviceaccount.com");
  });

  it("only strips a trailing .gserviceaccount.com, not an embedded occurrence", () => {
    // Defensive: the suffix is anchored to the end of the string.
    expect(
      toDbUsername(
        "postgres",
        "sa.gserviceaccount.com.x@project-id.iam.gserviceaccount.com"
      )
    ).toBe("sa.gserviceaccount.com.x@project-id.iam");
  });
});

describe("dbUsernameExceedsLimit", () => {
  // The reproducing case from terraform-provider-google#15520: a 30-char SA id
  // in a 30-char project id yields a 65-char username after stripping the
  // suffix — 2 over Postgres's 63-char limit, with no truncation workaround.
  const overLimitSa =
    "aaaa-bb-cccccccc-dddddd-eeeeee@ffffff-de-gggggggg-hhhh-iiiiii.iam";

  it("flags a Postgres service-account username over 63 chars", () => {
    // sanity: this fixture is genuinely over the limit
    expect(overLimitSa.length).toBeGreaterThan(MAX_POSTGRES_DB_USERNAME_LENGTH);
    expect(dbUsernameExceedsLimit("postgres", overLimitSa)).toBe(true);
  });

  it("accepts a Postgres username exactly at the 63-char limit", () => {
    const atLimit = "a".repeat(MAX_POSTGRES_DB_USERNAME_LENGTH);
    expect(atLimit.length).toBe(63);
    expect(dbUsernameExceedsLimit("postgres", atLimit)).toBe(false);
  });

  it("flags a Postgres username one char over the limit", () => {
    const overLimit = "a".repeat(MAX_POSTGRES_DB_USERNAME_LENGTH + 1);
    expect(dbUsernameExceedsLimit("postgres", overLimit)).toBe(true);
  });

  it("accepts a short Postgres username", () => {
    expect(dbUsernameExceedsLimit("postgres", "test-user@example.com")).toBe(
      false
    );
  });

  it("does not enforce a limit for MySQL yet (see TODO in cloudsql-user)", () => {
    // MySQL's 32-char limit applies to the stored (truncated) form and is not
    // guarded until the stored-name behavior is verified empirically.
    const longMysql = "a".repeat(100) + "@example.com";
    expect(dbUsernameExceedsLimit("mysql", longMysql)).toBe(false);
  });
});
