import { ConnectorError, LogEntrySchema } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import {
  PROJECT,
  adminActivity,
  bucketQuery,
  dataAccess,
  denied,
  impersonated,
  otherPrincipal,
  projectQuery,
} from "../../__tests__/fixtures.ts";
import { preciseTime, preciseWindow } from "../../time.ts";
import { entryMatches, toLogEntry } from "../entries.ts";
import { MAX_FILTER_LENGTH, composeFilter } from "../filter.ts";

const window = preciseWindow(projectQuery.window);

describe("composeFilter", () => {
  it("filters on the audit logs, the principal, the window and the permissions", () => {
    const { filter, permissionsPushedDown } = composeFilter(bucketQuery);
    expect(permissionsPushedDown).toBe(true);
    expect(filter).toBe(
      [
        `logName=("projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity" OR "projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access" OR "projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fsystem_event" OR "projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fpolicy")`,
        '(protoPayload.authenticationInfo.principalEmail="alice@example.com" OR protoPayload.authenticationInfo.serviceAccountDelegationInfo.firstPartyPrincipal.principalEmail="alice@example.com")',
        'timestamp>="2026-11-01T10:00:00Z"',
        'timestamp<"2026-11-01T12:00:00Z"',
        'protoPayload.authorizationInfo.permission=("storage.objects.get" OR "storage.objects.list")',
      ].join("\n")
    );
  });

  it("leaves permissions out when there are none", () => {
    const { filter, permissionsPushedDown } = composeFilter({
      ...bucketQuery,
      permissions: undefined,
    });
    expect(permissionsPushedDown).toBe(false);
    expect(filter).not.toContain("authorizationInfo");
  });

  it("falls back to narrowing when the permissions would make the filter too long", () => {
    const permissions = Array.from(
      { length: 1_000 },
      (_, i) => `compute.instances.permission${i}`
    );
    const { filter, permissionsPushedDown } = composeFilter({
      ...projectQuery,
      permissions,
    });
    expect(permissionsPushedDown).toBe(false);
    expect(filter.length).toBeLessThan(MAX_FILTER_LENGTH);
    expect(filter).not.toContain("authorizationInfo");
  });

  it("escapes quotes and rejects a malformed project", () => {
    expect(
      composeFilter({ ...projectQuery, principalEmail: 'a"b@example.com' })
        .filter
    ).toContain('principalEmail="a\\"b@example.com"');
    expect(() =>
      composeFilter({ ...projectQuery, projectId: 'p" OR "' })
    ).toThrow(ConnectorError);
  });
});

describe("toLogEntry", () => {
  it("normalizes Admin Activity", () => {
    const entry = toLogEntry(adminActivity);
    expect(entry).toEqual({
      id: "-k3x9c2e1a4b",
      time: "2026-11-01T10:20:11.482Z",
      action: "v1.compute.instances.insert",
      resource: `projects/${PROJECT}/zones/us-central1-a/instances/build-7`,
      result: "allowed",
      principal: "alice@example.com",
      raw: adminActivity,
    });
    expect(LogEntrySchema.parse(entry)).toEqual(entry);
  });

  it("normalizes Data Access", () => {
    expect(toLogEntry(dataAccess)).toMatchObject({
      action: "storage.objects.get",
      resource: "projects/_/buckets/acme-reports/objects/2026/q3.csv",
      result: "allowed",
    });
  });

  it("marks refusals denied", () => {
    expect(toLogEntry(denied).result).toBe("denied");
    expect(
      toLogEntry({
        ...dataAccess,
        protoPayload: {
          ...dataAccess.protoPayload,
          authorizationInfo: [{ permission: "x", granted: false }],
        },
      }).result
    ).toBe("denied");
    expect(
      toLogEntry({
        ...dataAccess,
        logName: `projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fpolicy`,
      }).result
    ).toBe("denied");
  });

  it("keeps the acting service account as the principal when impersonating", () => {
    expect(toLogEntry(impersonated).principal).toBe(
      "deployer@acme-prod-381204.iam.gserviceaccount.com"
    );
  });
});

describe("entryMatches", () => {
  it("keeps the principal's entries under a project-level grant", () => {
    expect(entryMatches(projectQuery, adminActivity, window)).toBe(true);
    expect(entryMatches(projectQuery, dataAccess, window)).toBe(true);
    expect(entryMatches(projectQuery, otherPrincipal, window)).toBe(false);
  });

  it("matches the impersonating principal, case-insensitively", () => {
    expect(entryMatches(projectQuery, impersonated, window)).toBe(true);
  });

  it("narrows by resource prefix on a path boundary", () => {
    expect(entryMatches(bucketQuery, dataAccess, window)).toBe(true);
    expect(
      entryMatches({ ...bucketQuery, permissions: undefined }, denied, window)
    ).toBe(false);
    expect(
      entryMatches(
        {
          ...bucketQuery,
          resourcePrefixes: [
            "//storage.googleapis.com/projects/_/buckets/acme-rep",
          ],
        },
        dataAccess,
        window
      )
    ).toBe(false);
  });

  it("narrows by permission and window", () => {
    expect(entryMatches(bucketQuery, adminActivity, window)).toBe(false);
    expect(
      entryMatches(projectQuery, dataAccess, {
        start: window.start,
        end: preciseTime(dataAccess.timestamp)!,
      })
    ).toBe(false);
  });

  it("compares the window past the millisecond", () => {
    const entry = { ...dataAccess, timestamp: "2026-11-01T10:31:02.109884Z" };
    const query = {
      ...projectQuery,
      window: {
        start: "2026-11-01T10:31:02.109800Z",
        end: "2026-11-01T10:31:02.109900Z",
      },
    };
    // Both bounds and the entry fall in the same millisecond.
    expect(entryMatches(query, entry, preciseWindow(query.window))).toBe(true);
    expect(
      entryMatches(
        query,
        entry,
        preciseWindow({ ...query.window, end: "2026-11-01T10:31:02.109884Z" })
      )
    ).toBe(false);
    // An offset is normalized.
    expect(preciseTime("2026-11-01T11:31:02.109884+01:00")).toBe(
      preciseTime(entry.timestamp)
    );
  });
});
