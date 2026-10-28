import { z } from "zod";

/**
 * The instance's one credential: the connector signs in to Harbor with it as
 * a dedicated Harbor admin user, for every call. It is a refresh token for
 * that user on Harbor's own OIDC client, from which the connector mints an ID
 * token once per connector call (harbor/oidc.ts).
 */
export type AdminCredential = {
  /** The OIDC issuer, https, without a trailing slash. */
  issuer: string;
  /** Harbor's OIDC client's ID: the ID token's audience. */
  clientId: string;
  /** A client secret of that client: P0's own where the provider allows a
   * second one, otherwise Harbor's. */
  clientSecret: string;
  /** The admin user's refresh token, with the `openid` scope. */
  refreshToken: string;
};

/** What the secret holds, for a message. Placeholders only. */
export const ADMIN_SECRET_SHAPE =
  '{"issuer": "<OIDC issuer URL>", "clientId": "<Harbor\'s OIDC client ID>", "clientSecret": "<client secret>", "refreshToken": "<refresh token>"}';

/**
 * The longest value a field may hold. A refresh token is opaque and a few
 * hundred characters at most at the providers Harbor supports. The cap keeps
 * a value that is plainly something else from going any further.
 */
export const MAX_FIELD_LENGTH = 8192;

// A value with something in it besides whitespace, and nothing that would
// break the form it is sent in.
const filled = z
  .string()
  .max(MAX_FIELD_LENGTH)
  .regex(/\S/)
  .regex(/^[^\r\n]*$/);

// The issuer is where the connector finds the token endpoint, and sends the
// refresh token and the client secret: https only, with no username,
// password, query or fragment. A path is allowed: some providers' issuers
// have one. It comes back without a trailing slash, so
// `<issuer>/.well-known/openid-configuration` has one slash.
const issuer = z.string().transform((value, ctx) => {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    ctx.addIssue({ code: "custom", message: "must be an https URL" });
    return z.NEVER;
  }
  const { protocol, username, password, search, hash, origin, pathname } =
    parsed;
  // `URL` drops an empty `?` or `#`, so the text is checked as well.
  if (
    protocol !== "https:" ||
    username !== "" ||
    password !== "" ||
    search !== "" ||
    hash !== "" ||
    value.includes("?") ||
    value.includes("#")
  ) {
    ctx.addIssue({ code: "custom", message: "must be an https URL" });
    return z.NEVER;
  }
  return `${origin}${pathname.replace(/\/+$/, "")}`;
});

const credentialJson = z.strictObject({
  issuer,
  clientId: filled,
  clientSecret: filled,
  refreshToken: filled,
});

const FIELDS: ReadonlySet<PropertyKey> = new Set(
  Object.keys(credentialJson.shape)
);

/**
 * The secret's value as an {@link AdminCredential}, or what is wrong with it
 * in the connector's own words. The problem names the fields that are
 * missing or don't parse, by the connector's names for them, and never a
 * value or a key it doesn't know: either may be the credential, pasted in
 * the wrong place.
 */
export const parseAdminCredential = (
  json: unknown
):
  | { ok: false; problem: string }
  | { ok: true; credential: AdminCredential } => {
  const parsed = credentialJson.safeParse(json);
  if (parsed.success) return { ok: true, credential: parsed.data };
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return { ok: false, problem: ": it isn't a JSON object" };
  }
  const fields = [
    ...new Set(
      parsed.error.issues
        .map(({ path: [field] }) => field)
        .filter((field) => field !== undefined && FIELDS.has(field))
        .map(String)
    ),
  ];
  const extra = parsed.error.issues.some(
    ({ code }) => code === "unrecognized_keys"
  );
  const problems = [
    ...(fields.length > 0
      ? [
          `${fields.join(", ")} ${fields.length === 1 ? "is" : "are"} missing or not valid`,
        ]
      : []),
    ...(extra
      ? [
          "it has fields besides issuer, clientId, clientSecret and refreshToken",
        ]
      : []),
  ];
  return {
    ok: false,
    problem: problems.length === 0 ? "" : `: ${problems.join(", and ")}`,
  };
};
