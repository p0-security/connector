import { ConnectorError, type Logger } from "@p0security/connector-core";
import { z } from "zod";

import type { Account } from "../account.ts";
import { memberId } from "../ids.ts";
import type { TokenKind } from "../install/definition.ts";
import { readToken } from "../secrets.ts";
import {
  type BodyOf,
  LAUNCHDARKLY_ROUTES,
  type LaunchDarklyApi,
  type LaunchDarklyCall,
  isStatus,
  newLaunchDarklyApi,
} from "./api.ts";

/**
 * Rows a page asks for: 20, the default that each list LaunchDarkly pages
 * documents. A limit above the server's own cap would make every page come
 * back short.
 */
export const PAGE_SIZE = 20;

/**
 * The most pages a listing reads before it gives up: 20,000 rows. A server
 * that never reaches its own total would otherwise be paged forever.
 */
export const MAX_PAGES = 1000;

/** The account and member behind the access token. */
export type CallerIdentity = {
  /** LaunchDarkly's id for the account. */
  accountId: string;
  /** `service` when `serviceToken` is true, `personal` otherwise. */
  tokenKind: TokenKind;
  /**
   * The member a personal token acts as, which the connector never changes.
   * `null` for a service token, which acts as no member.
   */
  tokenOwnerMemberId: string | null;
};

/** A member the email lookup found, and whether they can be given access. */
export type MemberMatch = {
  memberId: string;
  /** LaunchDarkly's spelling of the email, which matched ignoring case. */
  email: string;
  /** Whether the member verified the email. */
  verified: boolean;
  /** Whether the member is still an invitation, not yet joined. */
  pendingInvite: boolean;
};

/**
 * A member: who they are, and what they hold, which is their base role and
 * the custom roles assigned to them directly.
 */
export type MemberState = {
  memberId: string;
  /** LaunchDarkly's spelling of the member's email. */
  email: string;
  /** Whether the member verified the email. */
  verified: boolean;
  /** Whether the member is still an invitation, not yet joined. */
  pendingInvite: boolean;
  /** The base role, which applies only while the member has no custom role. */
  role: string;
  /** The `_id`s of the custom roles assigned to the member directly. */
  customRoleIds: string[];
};

// What `GET /caller-identity` is read for (the spec's `CallerIdentityRep`,
// whose fields are all optional). The rest of it, the token's name and id
// among it, is dropped by the parse.
const callerIdentityAnswer = z.object({
  accountId: z.string().min(1),
  memberId: memberId.optional(),
  serviceToken: z.boolean().optional(),
});

/** One page of a list: its items, and its total when it reports one. */
type Page<T> = { items: T[]; totalCount?: number };

const pageOf = <T>(item: z.ZodType<T>): z.ZodType<Page<T>> =>
  z.object({
    items: z.array(item),
    totalCount: z.number().int().nonnegative().optional(),
  });

// The spec's `Member`, as far as the email lookup reads it. `_verified` and
// `_pendingInvite` are required there, and here: a member without them
// fails the read rather than reading as verified or joined.
const memberRow = z.object({
  _id: z.string().min(1),
  _pendingInvite: z.boolean(),
  _verified: z.boolean(),
  email: z.string(),
});

// The spec's `Member`, as far as `member-state` and the grants read it.
// `customRoles` holds role ids. `email`, `_verified` and `_pendingInvite`
// are required there, and here.
const memberStateRow = memberRow.extend({
  customRoles: z.array(z.string()),
  role: z.string().min(1),
});

// A write's answer, which nothing is read from: a grant reads the member
// back to see its change.
const writeAnswer = z.object({});

/**
 * Every row of a paged list, page by page as the caller reads them. Each
 * page asks for {@link PAGE_SIZE} rows from where the last one ended. It
 * stops when the rows read reach the page's `totalCount`, or, for a list
 * that reports none, on a page shorter than {@link PAGE_SIZE}. An empty page
 * stops it too, since nothing can come after it.
 *
 * A page longer than {@link PAGE_SIZE}, or more than {@link MAX_PAGES}
 * pages, isn't how LaunchDarkly answers, and fails the listing.
 */
export async function* paged<T>(
  api: Pick<LaunchDarklyApi, "unexpected">,
  call: LaunchDarklyCall,
  readPage: (page: { limit: string; offset: string }) => Promise<Page<T>>
): AsyncGenerator<T, void, undefined> {
  let offset = 0;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { items, totalCount } = await readPage({
      limit: String(PAGE_SIZE),
      offset: String(offset),
    });
    if (items.length > PAGE_SIZE) throw api.unexpected(call, "too_many_rows");
    yield* items;
    offset += items.length;
    const last =
      totalCount === undefined
        ? items.length < PAGE_SIZE
        : offset >= totalCount || items.length === 0;
    if (last) return;
  }
  throw api.unexpected(call, "endless");
}

const collect = async <T>(rows: AsyncIterable<T>): Promise<T[]> => {
  const all: T[] = [];
  for await (const row of rows) all.push(row);
  return all;
};

/**
 * `text` with ASCII `A` to `Z` lowered, and nothing else changed. A copy of
 * the Harbor connector's.
 *
 * Emails are compared ignoring ASCII case only. `toLowerCase` folds Unicode
 * too: the Kelvin sign `K` (U+212A) lowers to `k`, so a member with a
 * look-alike email would match the principal.
 */
export const foldAsciiCase = (text: string) =>
  text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());

/** `undefined` when LaunchDarkly answers 404: there is nothing by that key. */
export const unlessNotFound = async <T>(
  run: () => Promise<T>
): Promise<T | undefined> => {
  try {
    return await run();
  } catch (error) {
    if (isStatus(error, 404)) return undefined;
    throw error;
  }
};

/**
 * How long one connector invocation may spend calling LaunchDarkly: 45
 * seconds, so that a call started just before it, with its own
 * `LAUNCHDARKLY_TIMEOUT_MS`, still ends inside the 60-second Lambda timeout.
 */
export const INVOCATION_BUDGET_MS = 45_000;

/** When an invocation started, and how long it may spend on LaunchDarkly. */
export type InvocationBudget = {
  budgetMs?: number;
  /** The clock. Tests pass one they move. */
  now?: () => number;
};

/**
 * `api` with one deadline for every call it makes: {@link
 * INVOCATION_BUDGET_MS} from now. A call that would start after it fails
 * with `upstream_unavailable` instead, so a long listing ends with a clear
 * error, not the deployment's timeout. A call already running finishes.
 */
export const withDeadline = (
  api: LaunchDarklyApi,
  { budgetMs = INVOCATION_BUDGET_MS, now = Date.now }: InvocationBudget = {}
): LaunchDarklyApi => {
  const deadline = now() + budgetMs;
  const check = (name: keyof typeof LAUNCHDARKLY_ROUTES) => {
    if (now() < deadline) return;
    const { method, route } = LAUNCHDARKLY_ROUTES[name];
    throw new ConnectorError({
      message: `The connector stopped before ${method} ${route}: it had spent the ${budgetMs / 1000} seconds one request may spend calling LaunchDarkly at ${api.host}. LaunchDarkly may be slow, or the account may list more than one request can read. Try again later.`,
      payload: { budgetMs, host: api.host },
      type: "upstream_unavailable",
    });
  };
  return {
    ...api,
    read: (request) => {
      check(request.route);
      return api.read(request);
    },
    write: (request) => {
      check(request.route);
      return api.write(request);
    },
  };
};

/**
 * The LaunchDarkly calls the connector makes, as the account's access token,
 * within one {@link withDeadline} deadline: build one per invocation. Every
 * method fails with a `LaunchDarklyError` for anything LaunchDarkly answers,
 * or doesn't, and with the deadline's `ConnectorError` once it passes. Wrap
 * calls in `callLaunchDarkly` to turn a `LaunchDarklyError` into the error
 * P0 shows.
 *
 * Callers check each id and key against its schema in `ids.ts` before they
 * pass it: each becomes a path segment.
 */
export const newLaunchDarklyClient = (
  unbounded: LaunchDarklyApi,
  budget?: InvocationBudget
) => {
  const api = withDeadline(unbounded, budget);

  return {
    host: api.host,

    /**
     * The account and member the token belongs to. A token that isn't a
     * service token is a personal one, which acts as a member, so an answer
     * without that member's id isn't one the connector can use.
     */
    fetchCallerIdentity: async (): Promise<CallerIdentity> => {
      const { accountId, memberId, serviceToken } = await api.read({
        answer: callerIdentityAnswer,
        route: "getCallerIdentity",
      });
      if (serviceToken === true) {
        return { accountId, tokenKind: "service", tokenOwnerMemberId: null };
      }
      if (memberId === undefined) {
        throw api.unexpected(
          LAUNCHDARKLY_ROUTES.getCallerIdentity,
          "wrong_shape"
        );
      }
      return { accountId, tokenKind: "personal", tokenOwnerMemberId: memberId };
    },

    /**
     * The members whose email is `email`, ignoring ASCII case
     * ({@link foldAsciiCase}), each once.
     *
     * One call asks for the email as given and ASCII-lowered: the filter's
     * `|` separates emails, and its `,` separates filters, so an email with
     * either is refused before any call.
     */
    listMembersByEmail: async (email: string): Promise<MemberMatch[]> => {
      if (/[,|]/.test(email)) {
        throw new ConnectorError({
          message:
            "The connector can't look a LaunchDarkly member up by an email with a `,` or a `|` in it.",
          payload: {},
          type: "validation_error",
        });
      }
      const wanted = foldAsciiCase(email);
      // REST check 1 (INT-719) records whether the filter matches an email
      // exactly, and whether it ignores case.
      const filter = `email:${[...new Set([email, wanted])].join("|")}`;
      const rows = await collect(
        paged(api, LAUNCHDARKLY_ROUTES.getMembers, (page) =>
          api.read({
            answer: pageOf(memberRow),
            query: { filter, ...page },
            route: "getMembers",
          })
        )
      );
      const matches = rows
        .filter((row) => foldAsciiCase(row.email) === wanted)
        .map((row): MemberMatch => ({
          email: row.email,
          memberId: row._id,
          pendingInvite: row._pendingInvite,
          verified: row._verified,
        }));
      // Each member once, as the last page that listed them has them.
      return [
        ...new Map(matches.map((match) => [match.memberId, match])).values(),
      ];
    },

    /**
     * The member's email and invite state, and their base role and the
     * custom roles assigned to them directly.
     */
    fetchMember: async (id: string): Promise<MemberState> => {
      const { _id, email, _verified, _pendingInvite, role, customRoles } =
        await api.read({
          answer: memberStateRow,
          params: { id },
          route: "getMember",
        });
      return {
        customRoleIds: customRoles,
        email,
        memberId: _id,
        pendingInvite: _pendingInvite,
        role,
        verified: _verified,
      };
    },

    /**
     * Applies a JSON Patch to the member, on `/role` only, with a `test`, as
     * the API's allowlist holds it. LaunchDarkly applies all of it or none
     * of it, and a failed `test` refuses it. Member patches carry no
     * comment: the spec documents none (REST check 11, INT-719).
     */
    patchMember: async (
      id: string,
      patch: BodyOf<"patchMember">
    ): Promise<void> => {
      await api.write({
        answer: writeAnswer,
        body: patch,
        params: { id },
        route: "patchMember",
      });
    },
  };
};

export type LaunchDarklyClient = ReturnType<typeof newLaunchDarklyClient>;

/**
 * A client for the account's instance, as the access token it reads from
 * the account's secret now. The token is read on every call, never kept.
 */
export const connectLaunchDarkly = async (
  { instance, secret }: Pick<Account, "instance" | "secret">,
  logger: Logger
): Promise<LaunchDarklyClient> =>
  newLaunchDarklyClient(
    newLaunchDarklyApi({
      instance,
      logger,
      token: await readToken(secret, logger),
    })
  );
