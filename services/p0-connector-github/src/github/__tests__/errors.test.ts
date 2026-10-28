import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { GitHubError } from "../api.ts";
import {
  AppNotInstalledError,
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
  TeamChangeRefusedError,
  TeamNotFoundError,
  isUnexplainedRefusal,
  toConnectorError,
} from "../errors.ts";

const target = { org: "acme", repo: "api", login: "octocat" };

// The path carries ids P0 must not post to a Slack or Teams channel.
const PATH = "/app/installations/4242/access_tokens";

const githubError = (
  status: number | undefined,
  githubMessages: string[],
  acceptedPermissions?: string
) =>
  new GitHubError({
    method: "POST",
    path: PATH,
    status,
    githubMessages,
    acceptedPermissions,
  });

const dataOf = (error: unknown) => {
  expect(error).toBeInstanceOf(ConnectorError);
  return (error as ConnectorError).data;
};

describe("toConnectorError", () => {
  it("names the permission GitHub asked for on a 403", () => {
    const data = dataOf(
      toConnectorError(
        githubError(
          403,
          ["Resource not accessible by integration"],
          "members=read"
        ),
        target
      )
    );
    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toBe(
      "The GitHub App for acme is missing members=read. Grant it in the app's settings and accept the update on the installation."
    );
  });

  it("names the permissions the installation lacks", () => {
    const data = dataOf(
      toConnectorError(
        new MissingPermissionsError(["administration=write"]),
        target
      )
    );
    expect(data.type).toBe("insufficient_privileges");
    expect(data.message).toContain("is missing administration=write.");
  });

  it("treats a 403 secondary rate limit as a rate limit", () => {
    const data = dataOf(
      toConnectorError(
        githubError(403, ["You have exceeded a secondary rate limit"]),
        target
      )
    );
    expect(data.type).toBe("rate_limited");
  });

  it.each([
    [
      401,
      "insufficient_privileges",
      "GitHub rejected the GitHub App credentials for acme. Check that the app ID and the private key in the connector's secret manager belong to the same app, that the key hasn't been revoked, and that the connector's clock is accurate.",
    ],
    [
      429,
      "rate_limited",
      "GitHub is rate limiting the GitHub App for acme. Retry in a few minutes.",
    ],
    [
      500,
      "upstream_unavailable",
      "GitHub couldn't answer the connector's request right now. Retry in a few minutes, and check githubstatus.com if it keeps failing.",
    ],
    [
      502,
      "upstream_unavailable",
      "GitHub couldn't answer the connector's request right now. Retry in a few minutes, and check githubstatus.com if it keeps failing.",
    ],
    [
      404,
      "object_not_found",
      "GitHub couldn't find octocat or api in acme. Check that it still exists, and that the GitHub App is still installed on acme.",
    ],
    [
      undefined,
      "upstream_unavailable",
      "The connector couldn't reach GitHub. Check that it can reach api.github.com, then retry.",
    ],
    [
      422,
      "unknown",
      "GitHub refused the connector's request for acme (422): Validation Failed; x",
    ],
  ])(
    "maps status %s to %s with a fixed message, never the path",
    (status, type, message) => {
      const error = githubError(status, ["Validation Failed", "x"]);
      expect(error.message).toContain(PATH);

      const data = dataOf(toConnectorError(error, target));

      expect(data.type).toBe(type);
      expect(data.message).toBe(message);
      expect(JSON.stringify(data)).not.toContain(PATH);
      expect(JSON.stringify(data)).not.toContain("4242");
    }
  );

  it("names only the org for a not-found with no repo or login", () => {
    const data = dataOf(
      toConnectorError(githubError(404, ["Not Found"]), { org: "acme" })
    );
    expect(data.message).toBe(
      "GitHub couldn't find acme. Check that it still exists, and that the GitHub App is still installed on acme."
    );
  });

  it("reports a 401 with its own reason", () => {
    const data = dataOf(
      toConnectorError(githubError(401, ["Bad credentials"]), target)
    );
    expect(data.payload).toEqual({
      reason: "credentials_rejected",
      org: "acme",
    });
  });

  it("reports an app that isn't installed on the org", () => {
    const data = dataOf(toConnectorError(new AppNotInstalledError(), target));
    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ reason: "not_installed", org: "acme" });
    expect(data.message).toBe(
      "The GitHub App isn't installed on acme. Install it on the org, or check the org name in the P0 install, then retry."
    );
  });

  it.each([
    ["found suspended", new InstallationSuspendedError()],
    [
      "refused by GitHub as suspended",
      githubError(403, ["This installation has been suspended"]),
    ],
  ])("reports an installation %s, not a missing permission", (_case, error) => {
    const data = dataOf(toConnectorError(error, target));
    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({
      reason: "installation_suspended",
      org: "acme",
    });
    expect(data.message).toBe(
      "The GitHub App's installation on acme is suspended. Ask an owner of acme to unsuspend it in the org's GitHub App settings, then retry."
    );
  });

  // Not a missing permission, which a change to the app wouldn't fix.
  it("reports a refusal from the org's IP allow list", () => {
    const data = dataOf(
      toConnectorError(
        githubError(403, [
          "Although you appear to have the correct authorization credentials, the `acme` organization has an IP allow list enabled, and your IP address is not permitted to access this resource.",
        ]),
        target
      )
    );
    expect(data.type).toBe("insufficient_privileges");
    expect(data.payload).toEqual({ reason: "ip_not_allowed", org: "acme" });
    expect(data.message).toBe(
      "acme's IP allow list doesn't include the connector's IP address, so GitHub refused the connector's request. Add the connector's outbound IP address to the org's allow list, then retry."
    );
  });

  it("asks the requester to get a repo outside the selection added, at request time", () => {
    const data = dataOf(
      toConnectorError(new RepositoryNotVisibleError("api"), target)
    );
    expect(data.type).toBe("object_not_found");
    expect(data.payload).toEqual({
      query: "acme/api",
      org: "acme",
      repo: "api",
    });
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection. Ask your GitHub admin to add it to the app."
    );
  });

  it("asks for manual intervention on a repo outside the selection, mid role change", () => {
    const data = dataOf(
      toConnectorError(new RepositoryNotVisibleError("api"), {
        ...target,
        changingAccess: true,
      })
    );
    expect(data.type).toBe("object_not_found");
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection, so P0 couldn't change octocat's role. Add the repo back to the app and retry, or change the role in GitHub."
    );
  });

  describe("a team", () => {
    const teamTarget = { org: "acme", team: "platform", login: "octocat" };

    it("that doesn't exist any more is object_not_found, by its id", () => {
      const data = dataOf(
        toConnectorError(new TeamNotFoundError("7"), {
          org: "acme",
          login: "octocat",
        })
      );
      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        query: "acme/7",
        org: "acme",
        teamId: "7",
      });
      expect(data.message).toBe(
        "The team with id 7 doesn't exist in acme any more. Request access to a team that does."
      );
    });

    it("that doesn't exist any more needs manual intervention mid membership change", () => {
      const data = dataOf(
        toConnectorError(new TeamNotFoundError("7"), {
          org: "acme",
          login: "octocat",
          changingAccess: true,
        })
      );
      expect(data.type).toBe("object_not_found");
      expect(data.message).toBe(
        "The team with id 7 doesn't exist in acme any more, so P0 couldn't add octocat to it. Request access to a team that does."
      );
    });

    it("whose members GitHub won't change is a validation_error, quoting GitHub", () => {
      const data = dataOf(
        toConnectorError(new TeamChangeRefusedError(["Forbidden"]), teamTarget)
      );
      expect(data.type).toBe("validation_error");
      expect(data.payload).toEqual({
        reason: "team_change_refused",
        org: "acme",
        team: "platform",
        login: "octocat",
      });
      expect(data.message).toBe(
        "GitHub refused to change who is on platform (Forbidden). If the team is synced with an identity provider group, change its members in the identity provider."
      );
    });

    it("is named in any other GitHub failure's payload and message", () => {
      const data = dataOf(
        toConnectorError(githubError(404, ["Not Found"]), teamTarget)
      );
      expect(data.type).toBe("object_not_found");
      expect(data.payload).toEqual({
        org: "acme",
        team: "platform",
        status: 404,
      });
      expect(data.message).toBe(
        "GitHub couldn't find octocat or platform in acme. Check that it still exists, and that the GitHub App is still installed on acme."
      );
    });
  });

  it("passes a ConnectorError through", () => {
    const error = new ConnectorError({
      type: "validation_error",
      message: "m",
      payload: {},
    });
    expect(toConnectorError(error, target)).toBe(error);
  });

  it("leaves anything else alone", () => {
    const error = new Error("a bug");
    expect(toConnectorError(error, target)).toBe(error);
  });
});

// A 403 means several things, and each of the others has its own fix.
describe("isUnexplainedRefusal", () => {
  it("is true for a 403 that none of the known ones explains", () => {
    expect(isUnexplainedRefusal(githubError(403, ["Forbidden"]))).toBe(true);
  });

  it.each([
    ["a missing permission", 403, "Resource not accessible by integration"],
    ["a suspended installation", 403, "This installation has been suspended"],
    ["a rate limit", 403, "You have exceeded a secondary rate limit."],
    [
      "the org's IP allow list",
      403,
      "Although you appear to have the correct authorization credentials, the `acme` organization has an IP allow list enabled, and your IP address is not permitted to access this resource.",
    ],
    ["another status", 404, "Not Found"],
  ])("is false for %s", (_case, status, message) => {
    expect(isUnexplainedRefusal(githubError(status, [message]))).toBe(false);
  });

  it("is false for anything that isn't a GitHub failure", () => {
    expect(isUnexplainedRefusal(new Error("a bug"))).toBe(false);
  });
});
