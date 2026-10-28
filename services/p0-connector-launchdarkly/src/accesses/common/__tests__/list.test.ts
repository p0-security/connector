import { describe, expect, it, vi } from "vitest";

import {
  ACCOUNT,
  API,
  EMAIL,
  LAUNCHDARKLY_HOST,
  MEMBER_ID,
  OTHER_ACCOUNT_ID,
  ROLE_ID,
  TOKEN_OWNER_ID,
  connectorError,
  logger,
  stubPatternAndToken,
} from "../../../__tests__/fixtures.ts";
import { DOMAIN_ALLOW_PATTERN_ENV } from "../../../allowlist.ts";
import {
  type FakeLaunchDarklyState,
  type FakeMember,
  PERSONAL_CALLER,
  fakeMember,
  newFakeLaunchDarkly,
} from "../../../launchdarkly/__tests__/fake-launchdarkly.ts";
import { readToken } from "../../../secrets.ts";
import type { ListerQuery } from "../definition.ts";
import { list } from "../list.ts";

// The secret manager is `secrets.test.ts`'s business. Here the read answers
// with the token.
vi.mock("../../../secrets.ts");

const OTHER_MEMBER_ID = "507f1f77bcf86cd799439012";

const run = (query: ListerQuery) => list(logger, query);

const queryMember = (email: string) =>
  run({ type: "member", context: ACCOUNT, email });

stubPatternAndToken();

describe("member", () => {
  const withMembers = (
    members: FakeMember[],
    overrides: FakeLaunchDarklyState = {}
  ) => newFakeLaunchDarkly({ members, ...overrides });

  it("answers the one member with the email, ignoring ASCII case, in one call for both spellings", async () => {
    const launchDarkly = withMembers([
      fakeMember({ _id: MEMBER_ID, email: EMAIL }),
      fakeMember({ _id: OTHER_MEMBER_ID, email: "someone-else@example.com" }),
    ]);

    await expect(queryMember("Sentinel-Person@Example.com")).resolves.toEqual([
      { key: MEMBER_ID, value: EMAIL },
    ]);
    expect(launchDarkly.calls()).toEqual([
      `GET ${API}/caller-identity`,
      `GET ${API}/members?filter=email%3ASentinel-Person%40Example.com%7Csentinel-person%40example.com&limit=20&offset=0`,
    ]);
  });

  it("asks for an email that is already lower case once", async () => {
    const launchDarkly = withMembers([
      fakeMember({ _id: MEMBER_ID, email: EMAIL }),
    ]);

    await expect(queryMember(EMAIL)).resolves.toEqual([
      { key: MEMBER_ID, value: EMAIL },
    ]);
    expect(launchDarkly.calls()[1]).toBe(
      `GET ${API}/members?filter=email%3Asentinel-person%40example.com&limit=20&offset=0`
    );
  });

  it("answers [] when no member has the email", async () => {
    withMembers([
      fakeMember({ _id: OTHER_MEMBER_ID, email: "someone-else@example.com" }),
    ]);

    await expect(queryMember(EMAIL)).resolves.toEqual([]);
  });

  it("answers [] for a member who hasn't accepted their invitation", async () => {
    withMembers([
      fakeMember({ _id: MEMBER_ID, _pendingInvite: true, email: EMAIL }),
    ]);

    await expect(queryMember(EMAIL)).resolves.toEqual([]);
  });

  // Members can change their own email, so an unverified one could be a
  // colleague's.
  it("answers [] for a member who hasn't verified the email", async () => {
    withMembers([
      fakeMember({ _id: MEMBER_ID, _verified: false, email: EMAIL }),
    ]);

    await expect(queryMember(EMAIL)).resolves.toEqual([]);
  });

  it("answers [] when two members have the email, in different cases", async () => {
    withMembers([
      fakeMember({ _id: MEMBER_ID, email: EMAIL }),
      fakeMember({
        _id: OTHER_MEMBER_ID,
        email: "Sentinel-Person@example.com",
      }),
    ]);

    await expect(queryMember("Sentinel-Person@example.com")).resolves.toEqual(
      []
    );
  });

  it("answers [] for the member a personal token acts as", async () => {
    withMembers([fakeMember({ _id: TOKEN_OWNER_ID, email: EMAIL })], {
      caller: PERSONAL_CALLER,
    });

    await expect(queryMember(EMAIL)).resolves.toEqual([]);
  });

  // With another account's token, the email could find a member there.
  it("refuses when the access token belongs to another account, before asking for members", async () => {
    const launchDarkly = withMembers(
      [fakeMember({ _id: MEMBER_ID, email: EMAIL })],
      {
        accountId: OTHER_ACCOUNT_ID,
      }
    );

    const error = await connectorError(() => queryMember(EMAIL));

    expect(error.data).toEqual({
      type: "validation_error",
      message: `The LaunchDarkly connector's access token on ${LAUNCHDARKLY_HOST} belongs to another account than the one P0 installed. Check the token in the account's secret, then request access again.`,
      payload: {
        host: LAUNCHDARKLY_HOST,
        changed: "account",
        reason: "member_changed",
      },
    });
    expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
  });

  it("answers [] for an email outside the allowed domains, before reading the secret", async () => {
    const launchDarkly = withMembers([
      fakeMember({ _id: MEMBER_ID, email: "sentinel-person@elsewhere.com" }),
    ]);

    await expect(queryMember("sentinel-person@elsewhere.com")).resolves.toEqual(
      []
    );
    expect(readToken).not.toHaveBeenCalled();
    expect(launchDarkly.calls()).toEqual([]);
  });

  it("refuses every email while the domain pattern is unset", async () => {
    vi.stubEnv(DOMAIN_ALLOW_PATTERN_ENV, "");
    const launchDarkly = withMembers([
      fakeMember({ _id: MEMBER_ID, email: EMAIL }),
    ]);

    const error = await connectorError(() => queryMember(EMAIL));

    expect(error.data).toMatchObject({
      type: "validation_error",
      payload: { reason: "domain_pattern_unusable" },
    });
    expect(launchDarkly.calls()).toEqual([]);
  });

  // `|` separates the filter's emails, and `,` its filters.
  it.each(["sentinel,person@example.com", "sentinel|person@example.com"])(
    "refuses %s before asking for members",
    async (email) => {
      const launchDarkly = withMembers([fakeMember({ _id: MEMBER_ID, email })]);

      const error = await connectorError(() => queryMember(email));

      expect(error.data.type).toBe("validation_error");
      expect(error.message).not.toContain(email);
      expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
    }
  );
});

describe("member-state", () => {
  it("answers the base role, then each direct custom role by its id, from the member alone", async () => {
    const launchDarkly = newFakeLaunchDarkly({
      members: [
        fakeMember({
          _id: MEMBER_ID,
          email: EMAIL,
          role: "writer",
          customRoles: [ROLE_ID],
        }),
      ],
    });

    await expect(
      run({ type: "member-state", context: ACCOUNT, memberId: MEMBER_ID })
    ).resolves.toEqual([
      { key: "role", value: "writer" },
      { key: ROLE_ID, value: ROLE_ID, group: "role" },
    ]);
    // No custom role is looked up.
    expect(launchDarkly.calls()).toEqual([
      `GET ${API}/caller-identity`,
      `GET ${API}/members/${MEMBER_ID}`,
    ]);
  });

  it("answers the base role alone for a member with no custom role", async () => {
    newFakeLaunchDarkly({
      members: [fakeMember({ _id: MEMBER_ID, email: EMAIL, role: "reader" })],
    });

    await expect(
      run({ type: "member-state", context: ACCOUNT, memberId: MEMBER_ID })
    ).resolves.toEqual([{ key: "role", value: "reader" }]);
  });

  // With another account's token, the id could read a member there.
  it("refuses when the access token belongs to another account, before reading the member", async () => {
    const launchDarkly = newFakeLaunchDarkly({
      accountId: OTHER_ACCOUNT_ID,
      members: [fakeMember({ _id: MEMBER_ID, email: EMAIL })],
    });

    const error = await connectorError(() =>
      run({ type: "member-state", context: ACCOUNT, memberId: MEMBER_ID })
    );

    expect(error.data).toMatchObject({
      type: "validation_error",
      payload: {
        host: LAUNCHDARKLY_HOST,
        changed: "account",
        reason: "member_changed",
      },
    });
    expect(launchDarkly.calls()).toEqual([`GET ${API}/caller-identity`]);
  });

  // `GET /members/me` reads the token's own member.
  it("refuses the member id `me` before any call", async () => {
    const launchDarkly = newFakeLaunchDarkly();

    await expect(
      run({ type: "member-state", context: ACCOUNT, memberId: "me" })
    ).rejects.toThrow();
    expect(readToken).not.toHaveBeenCalled();
    expect(launchDarkly.calls()).toEqual([]);
  });
});
