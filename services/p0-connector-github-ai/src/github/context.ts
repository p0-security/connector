/** GitHub permission levels accepted by the installation access token API. */
type AccessLevel = "admin" | "read" | "write";

export type AccessTokenRequest = {
  /** Repo name to scope the token to. */
  repository: string;
  /** Permission map to scope the token to. */
  permissions: Record<string, AccessLevel>;
};

/** Everything needed to mint a GitHub installation access token; the backend supplies all of it per request (the connector holds no GitHub state). */
export type GithubClientContext = {
  /** Github private key to mint JWT tokens*/
  privateKey: string;
  /** GitHub App id (JWT `iss` claim); the installation is discovered at mint time (App expected to be installed on the customer's single org). Accepts the numeric App id or its string form. */
  appId: number | string;
};
