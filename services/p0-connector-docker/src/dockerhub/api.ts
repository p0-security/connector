import { ConnectorError, type Logger } from "@p0security/connector-core";
import { compact } from "lodash-es";
import { z } from "zod";

import type { CoreRole } from "../accesses/role/definition.ts";

const DOCKER_HUB_BASE = "https://hub.docker.com";
const API_TIMEOUT = 10_000;

/** The most members Docker Hub returns on one page. */
export const PAGE_SIZE = 100;

type Method = "DELETE" | "GET" | "POST" | "PUT";

/**
 * A Docker Hub API call that failed.
 *
 * The request is never attached: its headers hold the JWT, and the token
 * exchange's body holds the organization access token.
 */
export class DockerHubError extends Error {
  /** The HTTP status, or `undefined` when Docker Hub didn't answer. */
  readonly status: number | undefined;
  /** Docker Hub's own messages, from the body's `message` and `detail`. */
  readonly dockerMessages: string[];
  /** `Retry-After` on a 429, in seconds. */
  readonly retryAfter: string | undefined;

  constructor(params: {
    method: Method;
    path: string;
    status: number | undefined;
    dockerMessages: string[];
    retryAfter?: string;
  }) {
    const { method, path, status, dockerMessages } = params;
    super(
      `Docker Hub ${method} ${path} failed${status === undefined ? "" : ` (${status})`}: ${
        dockerMessages[0] ?? "no message"
      }`
    );
    this.name = "DockerHubError";
    this.status = status;
    this.dockerMessages = dockerMessages;
    this.retryAfter = params.retryAfter;
  }
}

// Docker Hub's error bodies are `{ message, errinfo }` or `{ detail }`.
const errorBody = z.object({
  message: z.string().nullish(),
  detail: z.string().nullish(),
});

const messagesOf = (data: unknown): string[] => {
  const parsed = errorBody.safeParse(data);
  return parsed.success
    ? compact([parsed.data.message, parsed.data.detail])
    : [];
};

const REDACTED = "[redacted]";

// A refusal's text is quoted to the requestor, and nothing promises Docker
// Hub never quotes a request back. `fetch` does: its error for a header value
// it won't send quotes the whole `Authorization` header.
const withoutJwt = (messages: string[], jwt: string | undefined): string[] =>
  jwt === undefined
    ? messages
    : messages.map((message) =>
        // `split`/`join` rather than `replaceAll`: P0's backend type-checks this
        // file against an ES2017 lib through the connector's router type.
        message.split(`Bearer ${jwt}`).join(REDACTED).split(jwt).join(REDACTED)
      );

// How many causes under an error the log follows.
const MAX_CAUSES = 4;

/** The error and each cause under it, outermost first. */
const withCauses = (error: unknown, depth = 0): unknown[] =>
  error instanceof Error && error.cause !== undefined && depth < MAX_CAUSES
    ? [error, ...withCauses(error.cause, depth + 1)]
    : [error];

/**
 * Why a request got no answer, for the log: the error and its causes, where
 * `fetch` keeps the network's own reason, as text with the JWT cut out. The
 * error itself is never logged, because its message, and the stack that
 * repeats it, can hold the JWT.
 */
const failureOf = (error: unknown, jwt: string | undefined): string[] =>
  withoutJwt(withCauses(error).map(String), jwt);

const readBody = async (response: Response): Promise<unknown> => {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

type DockerHubRequest = {
  log: Logger;
  method: Method;
  /** The path, with every segment and query value already encoded. */
  path: string;
  /** The JWT, on every call but the token exchange. */
  jwt?: string;
  body?: unknown;
  /**
   * The body carries the organization access token. Docker Hub's error text
   * is then dropped, and a redirect fails the call instead of resending it.
   */
  carriesToken?: boolean;
};

/** Sends one request, and returns the response's body. */
const dockerHubRequest = async ({
  log,
  method,
  path,
  jwt,
  body,
  carriesToken = false,
}: DockerHubRequest): Promise<unknown> => {
  let response: Response;
  let data: unknown;
  try {
    response = await fetch(`${DOCKER_HUB_BASE}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        ...(jwt !== undefined ? { Authorization: `Bearer ${jwt}` } : {}),
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      // A cross-origin redirect drops the Authorization header, but a 307 or
      // 308 resends the body.
      redirect: carriesToken ? "error" : "follow",
      signal: AbortSignal.timeout(API_TIMEOUT),
    });
    // Inside the `try`: the connection can still drop while the body arrives.
    data = await readBody(response);
  } catch (error) {
    log.error(
      { method, path, failure: failureOf(error, jwt) },
      "Docker Hub request failed"
    );
    throw new DockerHubError({
      method,
      path,
      status: undefined,
      dockerMessages: withoutJwt(
        [error instanceof Error ? error.message : String(error)],
        jwt
      ),
    });
  }

  if (!response.ok) {
    const error = new DockerHubError({
      method,
      path,
      status: response.status,
      dockerMessages: carriesToken ? [] : withoutJwt(messagesOf(data), jwt),
      retryAfter: response.headers.get("retry-after") ?? undefined,
    });
    log.warn(
      {
        method,
        path,
        status: error.status,
        dockerMessages: error.dockerMessages,
        retryAfter: error.retryAfter,
      },
      "Docker Hub request returned a non-2xx response"
    );
    throw error;
  }

  log.debug(
    { method, path, status: response.status },
    "Docker Hub request succeeded"
  );
  return data;
};

/**
 * Reads a response body with `schema`, or fails as `unknown`: Docker Hub
 * answered in a shape the connector doesn't know, which nobody can fix.
 */
const parseResponse = <T>(params: {
  log: Logger;
  schema: z.ZodType<T>;
  data: unknown;
  what: string;
}): T => {
  const { log, schema, data, what } = params;
  const parsed = schema.safeParse(data);
  if (parsed.success) return parsed.data;
  log.warn(
    {
      what,
      // Where each issue is and its code, never a value: one body is a JWT.
      issues: parsed.error.issues.map(({ path, code }) => ({
        path: path.join("."),
        code,
      })),
    },
    "Docker Hub returned a response the connector can't read"
  );
  throw new ConnectorError({
    type: "unknown",
    message: `Docker Hub returned ${what} in a shape the connector doesn't recognize.`,
    payload: { what },
  });
};

/**
 * One URL path segment. `encodeURIComponent` leaves `.` and `..` alone, and
 * `fetch` would resolve them away, so they're refused here.
 */
const segment = (value: string): string => {
  if (value === "" || value === "." || value === "..") {
    throw new ConnectorError({
      type: "validation_error",
      message: `"${value}" isn't a valid Docker Hub name.`,
      payload: { segment: value },
    });
  }
  return encodeURIComponent(value);
};

// A JWT is base64 text and dots. Nothing else is taken as one: a line break,
// say, isn't legal in a header, and `fetch` would refuse to send it with an
// error that quotes the whole `Authorization` header.
const tokenResponse = z.object({
  access_token: z.string().regex(/^[A-Za-z0-9_.+/=-]+$/),
});

/** `POST /v2/auth/token`: exchanges the organization access token for a JWT. */
export const exchangeToken = async ({
  log,
  org,
  token,
}: {
  log: Logger;
  org: string;
  token: string;
}): Promise<string> => {
  const data = await dockerHubRequest({
    log,
    method: "POST",
    path: "/v2/auth/token",
    body: { identifier: org, secret: token },
    carriesToken: true,
  });
  return parseResponse({
    log,
    schema: tokenResponse,
    data,
    what: "the token exchange's response",
  }).access_token;
};

/** What every other call carries: the JWT, and the org it's for. */
export type OrgCall = { log: Logger; jwt: string; org: string };

/** An org member, with its role in the form `PUT` takes it. */
export type OrgMember = {
  username: string;
  uuid: string;
  email: string | undefined;
  /** A core role, lower-case, or a custom role's name. */
  role: string;
};

const member = z
  .object({
    username: z.string().min(1),
    uuid: z.string().min(1),
    // A member without an email never matches one.
    email: z.string().nullish(),
    // `Owner`, `Editor` or `Member`, capitalised.
    role: z.string().min(1),
    // Not in Docker Hub's API reference, but on every member INT-213 listed.
    assigned_role: z
      .object({ name: z.string().min(1), is_system: z.boolean().nullish() })
      .nullish(),
  })
  .transform(({ username, uuid, email, role, assigned_role }): OrgMember => ({
    username,
    uuid,
    email: email ?? undefined,
    // `role` only ever names a core role, so a custom one comes from here.
    role:
      assigned_role?.is_system === false
        ? assigned_role.name
        : role.toLowerCase(),
  }));

const memberPage = z.object({
  next: z.string().nullish(),
  results: z.array(member),
});

/**
 * One page of `GET /v2/orgs/{org}/members`, which leaves out pending
 * invitees. `search` also matches a username prefix and an email's local
 * part, so the caller picks out the exact match.
 */
export const listMembers = async ({
  log,
  jwt,
  org,
  search,
  page,
  pageSize,
}: OrgCall & {
  search?: string;
  page: number;
  pageSize: number;
}): Promise<{ members: OrgMember[]; hasNext: boolean }> => {
  const query = new URLSearchParams({
    ...(search !== undefined ? { search } : {}),
    page: String(page),
    page_size: String(pageSize),
  });
  const data = await dockerHubRequest({
    log,
    method: "GET",
    path: `/v2/orgs/${segment(org)}/members?${query.toString()}`,
    jwt,
  });
  const { next, results } = parseResponse({
    log,
    schema: memberPage,
    data,
    what: "a page of org members",
  });
  // The `next` link itself is never followed: the JWT only goes to a URL the
  // connector built.
  return { members: results, hasNext: Boolean(next) };
};

/** `PUT /v2/orgs/{org}/members/{username}`: sets the member's role. Repeating it changes nothing. */
export const putMemberRole = async ({
  log,
  jwt,
  org,
  username,
  role,
}: OrgCall & { username: string; role: CoreRole }): Promise<void> => {
  await dockerHubRequest({
    log,
    method: "PUT",
    path: `/v2/orgs/${segment(org)}/members/${segment(username)}`,
    jwt,
    body: { role },
  });
};

/** `DELETE /v2/orgs/{org}/members/{username}`: removes the member. Docker Hub refuses to remove the last owner. */
export const deleteMember = async ({
  log,
  jwt,
  org,
  username,
}: OrgCall & { username: string }): Promise<void> => {
  await dockerHubRequest({
    log,
    method: "DELETE",
    path: `/v2/orgs/${segment(org)}/members/${segment(username)}`,
    jwt,
  });
};

/** A pending invite, with its role lower-case. */
export type OrgInvite = {
  id: string;
  /** An email, or a Docker ID for someone an admin invited by username. */
  invitee: string;
  role: string;
};

const invite = z
  .object({
    id: z.string().min(1),
    invitee: z.string(),
    role: z.string().min(1),
  })
  .transform(({ id, invitee, role }): OrgInvite => ({
    id,
    invitee,
    role: role.toLowerCase(),
  }));

const inviteList = z.object({ data: z.array(invite) });

/** `GET /v2/orgs/{org}/invites`: every pending invite to the org. */
export const listInvites = async ({
  log,
  jwt,
  org,
}: OrgCall): Promise<OrgInvite[]> => {
  const data = await dockerHubRequest({
    log,
    method: "GET",
    path: `/v2/orgs/${segment(org)}/invites`,
    jwt,
  });
  return parseResponse({
    log,
    schema: inviteList,
    data,
    what: "the org's invites",
  }).data;
};

/** An invite to send: the email it goes to, and the core role it gives. */
export type NewInvite = { email: string; role: CoreRole };

// `POST /v2/invites/bulk` for one email, which both invites below send.
const postBulkInvite = ({
  log,
  jwt,
  org,
  email,
  role,
  dryRun,
}: OrgCall & NewInvite & { dryRun: boolean }): Promise<unknown> =>
  dockerHubRequest({
    log,
    method: "POST",
    path: "/v2/invites/bulk",
    jwt,
    body: {
      org,
      role,
      invitees: [email],
      ...(dryRun ? { dry_run: true } : {}),
    },
  });

/**
 * What Docker Hub did with an invite. Every status but the two it's known to
 * act on, such as `invalid_email_or_docker_id`, is a refusal.
 */
export type InviteResult =
  | { status: "existing_org_member" }
  | { status: "invited" }
  | { status: "refused"; reason: string };

const inviteReply = z.object({
  invitees: z.tuple([z.object({ status: z.string().min(1) })], z.unknown()),
});

/**
 * Reads the result of an invite of one email from Docker Hub's reply to it.
 *
 * It takes the reply's first entry rather than the one for the address,
 * because Docker Hub may echo a Docker ID in its place.
 */
export const readInviteResult = (log: Logger, data: unknown): InviteResult => {
  const [{ status }] = parseResponse({
    log,
    schema: inviteReply,
    data,
    what: "the invite's result",
  }).invitees;
  return status === "invited" || status === "existing_org_member"
    ? { status }
    : { status: "refused", reason: status };
};

/** `POST /v2/invites/bulk`: invites one email, and says what Docker Hub did with the invite. */
export const postInvite = async (
  invite: OrgCall & NewInvite
): Promise<InviteResult> =>
  readInviteResult(
    invite.log,
    await postBulkInvite({ ...invite, dryRun: false })
  );

/**
 * The same request as a dry run: Docker Hub validates the invite without
 * sending it or using a seat. The reply isn't read, so any 2xx passes.
 */
export const postDryRunInvite = async (
  invite: OrgCall & NewInvite
): Promise<void> => {
  await postBulkInvite({ ...invite, dryRun: true });
};

/** `DELETE /v2/invites/{id}`: cancels a pending invite. */
export const deleteInvite = async ({
  log,
  jwt,
  id,
}: {
  log: Logger;
  jwt: string;
  id: string;
}): Promise<void> => {
  await dockerHubRequest({
    log,
    method: "DELETE",
    path: `/v2/invites/${segment(id)}`,
    jwt,
  });
};
