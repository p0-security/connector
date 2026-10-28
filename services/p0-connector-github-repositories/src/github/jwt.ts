import { ConnectorError } from "@p0security/connector";
import jwt from "jsonwebtoken";

// Backdate `iat` by this many seconds to tolerate clock drift between us and GitHub.
const CLOCK_DRIFT_SECONDS = 60;
// JWT lifetime: 9 minutes, staying under GitHub's 10-minute maximum.
const EXPIRY_SECONDS = 9 * 60;

type CreateAppJwtParams = {
  /** GitHub App id, used as the JWT issuer (`iss`). */
  appId: string;
  /** The App's PEM-encoded RSA private key. */
  privateKey: string;
};

/** Signs a short-lived GitHub App JWT (RS256): `iat` backdated 60s for clock drift, `exp` 9 minutes out (GitHub rejects beyond 10). */
export const createAppJwt = ({ appId, privateKey }: CreateAppJwtParams) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const iat = nowSeconds - CLOCK_DRIFT_SECONDS;
  try {
    return jwt.sign(
      { iat, exp: iat + EXPIRY_SECONDS, iss: appId },
      privateKey,
      {
        algorithm: "RS256",
      }
    );
  } catch {
    // The signing error is dropped on purpose: what it says is about the key,
    // and nothing about the key belongs in an error.
    throw new ConnectorError({
      type: "validation_error",
      message: `The private key for GitHub App ${appId} isn't a valid PEM private key. Store the .pem file GitHub generated for the app.`,
      payload: { appId },
    });
  }
};
