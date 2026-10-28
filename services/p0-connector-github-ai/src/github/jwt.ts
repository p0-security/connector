import jwt from "jsonwebtoken";

import type { GithubAuth } from "./github-api.ts";

// Backdate `iat` by this many seconds to tolerate clock drift between us and GitHub.
const CLOCK_DRIFT_SECONDS = 60;
// JWT lifetime: 9 minutes, staying under GitHub's 10-minute maximum.
const EXPIRY_SECONDS = 9 * 60;

type CreateAppJwtParams = {
  /** GitHub App id, used as the JWT issuer (`iss`). */
  appId: number | string;
  /** The App's PEM-encoded RSA private key. */
  privateKey: string;
};

/** Signs a short-lived GitHub App JWT (RS256): `iat` backdated 60s for clock drift, `exp` 9 minutes out (GitHub rejects beyond 10). */
export const createAppJwt = ({
  appId,
  privateKey,
}: CreateAppJwtParams): GithubAuth => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const iat = nowSeconds - CLOCK_DRIFT_SECONDS;
  return {
    token: jwt.sign(
      {
        iat,
        exp: iat + EXPIRY_SECONDS,
        iss: String(appId),
      },
      privateKey,
      { algorithm: "RS256" }
    ),
  };
};
