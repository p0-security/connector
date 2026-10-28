import { ConnectorError, createLogger, isDefined } from "@p0security/connector";

import {
  type GithubAuth,
  type VerifiedInstallation,
  getAppInstallations,
} from "./github-api.ts";

const logger = createLogger();

/** Resolves the App's sole installation id, throwing on zero or more than one so a missing install or unexpected multi-account setup surfaces loudly instead of minting a token against the wrong account. */
export const getSoleInstallationId = async (
  auth: GithubAuth
): Promise<number> => {
  const installations = await getAppInstallations(auth);
  // we only consider the installations that have an accountLogin
  const verifiedInstallations: VerifiedInstallation[] = installations
    .map(({ id, accountLogin }) =>
      accountLogin ? { id, accountLogin } : undefined
    )
    .filter(isDefined);
  if (verifiedInstallations.length === 0) {
    logger.warn("no GitHub App installation found");
    throw new ConnectorError({
      type: "object_not_found",
      message:
        "No GitHub App installation found. Install the App on the target account first.",
      payload: {},
    });
  }
  if (verifiedInstallations.length > 1) {
    const accounts = verifiedInstallations
      .map((installation) => installation.accountLogin)
      .join(", ");
    logger.warn(
      { count: verifiedInstallations.length, accounts },
      "expected exactly one GitHub App installation but found more than one"
    );
    throw new ConnectorError({
      type: "unknown",
      message: `Expected exactly one GitHub App installation but found ${installations.length}: ${accounts}.`,
      payload: { installations: installations.length },
    });
  }

  return installations[0].id;
};
