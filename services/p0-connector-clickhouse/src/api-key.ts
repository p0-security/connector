import { z } from "zod";

/**
 * The organization's one credential: a ClickHouse Cloud API key. The
 * connector sends it as Basic auth to the Cloud API and to P0's own Query API
 * endpoints.
 */
export type ApiKey = {
  /** The key ID: Basic auth's user name. Not a secret. */
  keyId: string;
  /** The key secret: Basic auth's password. */
  keySecret: string;
};

/** What the secret holds, for a message. Placeholders only. */
export const API_KEY_SHAPE =
  '{"keyId": "<the API key ID>", "keySecret": "<the API key secret>"}';

/**
 * The key ID goes into Basic auth before a `:`, so it can't hold one. The
 * Cloud console's IDs are letters and digits.
 */
const keyId = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);

/**
 * The key secret is printable ASCII without spaces. Anything else, such as a
 * line break, isn't legal in a header, and `fetch` would refuse to send it
 * with an error that quotes the whole `Authorization` header.
 */
const keySecret = z.string().regex(/^[\x21-\x7E]{1,1024}$/);

const apiKeyJson = z.strictObject({ keyId, keySecret });

const FIELDS: ReadonlySet<PropertyKey> = new Set(Object.keys(apiKeyJson.shape));

/**
 * The secret's value as an {@link ApiKey}, or what is wrong with it in the
 * connector's own words. The problem names the fields that are missing or
 * don't parse, by the connector's names for them, and never a value or a key
 * it doesn't know: either may be the key secret, pasted in the wrong place.
 */
export const parseApiKey = (
  json: unknown
): { apiKey: ApiKey; ok: true } | { ok: false; problem: string } => {
  const parsed = apiKeyJson.safeParse(json);
  if (parsed.success) return { ok: true, apiKey: parsed.data };
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
    ...(extra ? ["it has fields besides keyId and keySecret"] : []),
  ];
  return {
    ok: false,
    problem: problems.length === 0 ? "" : `: ${problems.join(", and ")}`,
  };
};
