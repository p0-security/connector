import { describe, expect, it } from "vitest";

import { accountsUrl, workspaceUrl } from "../context.ts";

describe("accountsUrl", () => {
  it.each([
    "https://accounts.cloud.databricks.com",
    "https://accounts.azuredatabricks.net",
    "https://accounts.gcp.databricks.com",
  ])("accepts the account console %s", (url) => {
    expect(accountsUrl.parse(url)).toBe(url);
  });

  it("normalizes a trailing slash away", () => {
    expect(accountsUrl.parse("https://accounts.cloud.databricks.com/")).toBe(
      "https://accounts.cloud.databricks.com"
    );
  });

  it.each([
    "http://accounts.cloud.databricks.com",
    "https://accounts.cloud.databricks.com.evil.io",
    "https://evil.io/accounts.cloud.databricks.com",
    "https://accounts.cloud.databricks.com:8443",
    "https://accounts.cloud.databricks.com/oidc",
    "https://accounts.cloud.databricks.com?x=1",
    "https://user:pass@accounts.cloud.databricks.com",
    "https://dbc-1234.cloud.databricks.com",
    "not a url",
  ])("rejects %s", (url) => {
    expect(accountsUrl.safeParse(url).success).toBe(false);
  });
});

describe("workspaceUrl", () => {
  it.each([
    "https://dbc-1234abcd-5678.cloud.databricks.com",
    "https://adb-1234567890123456.7.azuredatabricks.net",
    "https://1234567890123456.7.gcp.databricks.com",
  ])("accepts the workspace %s", (url) => {
    expect(workspaceUrl.parse(url)).toBe(url);
  });

  it.each([
    "https://cloud.databricks.com",
    "https://evilcloud.databricks.com.evil.io",
    "https://dbc-1234.cloud.databricks.com.evil.io",
    "https://evil-azuredatabricks.net",
    "http://dbc-1234.cloud.databricks.com",
    "https://dbc-1234.cloud.databricks.com/api/2.0",
  ])("rejects %s", (url) => {
    expect(workspaceUrl.safeParse(url).success).toBe(false);
  });
});
