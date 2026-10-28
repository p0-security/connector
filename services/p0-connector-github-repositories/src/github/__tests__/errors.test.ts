import { ConnectorError } from "@p0security/connector-core";
import { describe, expect, it } from "vitest";

import { GitHubError } from "../api.ts";
import {
  AppNotInstalledError,
  InstallationSuspendedError,
  MissingPermissionsError,
  RepositoryNotVisibleError,
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
        changingRole: true,
      })
    );
    expect(data.type).toBe("object_not_found");
    expect(data.message).toBe(
      "api isn't in the GitHub App's repository selection, so P0 couldn't change octocat's role. Add the repo back to the app and retry, or change the role in GitHub."
    );
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
