/**
 * Argo CD's RBAC policy as the connector reads it from `argocd-rbac-cm`, and
 * the lines the connector writes to its own key, `policy.p0.csv`.
 *
 * Reading follows Argo CD's loader (`util/rbac/rbac.go`, read from source,
 * not checked live): every `policy*.csv` key, `policy.csv` first and the rest
 * in key order; each line trimmed; blank lines and lines starting with `#`
 * skipped; the rest read as one CSV record by Go's reader with leading space
 * trimmed. A `g` line has three fields and a `p` line six. Argo CD refuses
 * the whole policy over any other line, and keeps the policy it had: such a
 * line is counted in {@link RbacPolicy.refusedLines}, so a caller can tell
 * that what Argo CD enforces may not be what the ConfigMap says.
 *
 * Writing is strict: the connector builds every line it writes itself, from
 * typed fields, in one spelling, and only ever adds or removes a line in
 * that spelling.
 */
import type { ArgoCdProject } from "./client.ts";

/** The local account the connector acts as. */
export const CONNECTOR_ACCOUNT = "p0-connector";

/** The role the customer gives the connector's `p0-connector` account. */
export const CONNECTOR_ROLE = `role:${CONNECTOR_ACCOUNT}`;

/** The roles every Argo CD has. */
export const BUILT_IN_ROLES = ["role:readonly", "role:admin"] as const;

/**
 * What P0 grants: a global role, as `role:<name>`, or a role an AppProject
 * defines, by the project's name and the role's.
 */
export type Grant =
  | { kind: "global"; role: string }
  | { kind: "project"; project: string; role: string };

/** Why {@link buildLine} refused its fields. */
export type PolicyLineRefusal =
  /** The role is the connector's own, {@link CONNECTOR_ROLE}. */
  | "connector_role"
  /** The email isn't one P0 writes: see {@link EMAIL}. */
  | "email"
  /** The project isn't an AppProject name: see {@link PROJECT}. */
  | "project"
  /**
   * The role isn't one P0 writes: see {@link GLOBAL_ROLE} and
   * {@link PROJECT_ROLE}.
   */
  | "role";

/**
 * {@link buildLine}'s refusal. It names the field it refused, never the
 * value.
 */
export class PolicyLineError extends Error {
  constructor(readonly reason: PolicyLineRefusal) {
    super(`not a line P0 writes: bad ${reason}`);
    this.name = "PolicyLineError";
  }
}

declare const p0Line: unique symbol;

/** A line only {@link buildLine} makes, in P0's one spelling. */
export type P0Line = string & { readonly [p0Line]: true };

/**
 * An email P0 writes, in either case: a local part of letters, digits and
 * `._%+-'`, up to 64; an `@`; and two or more dot-separated labels of
 * letters, digits and inner hyphens, each up to 63. No `,`, `#`, quote,
 * space or newline can be in one.
 */
const EMAIL =
  /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

/** The most characters in an email: RFC 5321's path, less its brackets. */
const MAX_EMAIL = 254;

/**
 * A global role P0 writes: `role:` and a name of printable ASCII other than
 * space, `,`, `#` and `"`, so it can't end the field, the line or the
 * record. At most 253 in all.
 */
const GLOBAL_ROLE = /^role:[\x21-\x7e]{1,248}$/;
const NOT_IN_A_FIELD = /[,#"]/;

/**
 * An AppProject's name, which is a Kubernetes object name: dot-separated
 * parts of lowercase letters, digits and inner hyphens. At most 253.
 */
const PROJECT =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;

/**
 * An AppProject role's name, as Argo CD checks it: letters, digits, `-` and
 * `_`, starting and ending with a letter or a digit. At most 253.
 */
const PROJECT_ROLE = /^[a-zA-Z0-9](?:[-_a-zA-Z0-9]*[a-zA-Z0-9])?$/;

const MAX_NAME = 253;

const refuse = (reason: PolicyLineRefusal): never => {
  throw new PolicyLineError(reason);
};

/** `email`, if P0 writes it, in lower case. */
const checkedEmail = (email: string): string =>
  email.length <= MAX_EMAIL && EMAIL.test(email)
    ? email.toLowerCase()
    : refuse("email");

/**
 * Whether `role` is spelled as a global role P0 writes. The connector's own
 * role is spelled so too: {@link buildLine} refuses it on its own.
 */
export const isGlobalRole = (role: string): boolean =>
  GLOBAL_ROLE.test(role) && !NOT_IN_A_FIELD.test(role);

/** Whether `project` is an AppProject name P0 writes. */
export const isProjectName = (project: string): boolean =>
  project.length <= MAX_NAME && PROJECT.test(project);

/** Whether `role` is an AppProject role name P0 writes. */
export const isProjectRole = (role: string): boolean =>
  role.length <= MAX_NAME && PROJECT_ROLE.test(role);

/** The subject `grant`'s role has in a `g` line, if P0 writes it. */
const checkedRole = (grant: Grant): string => {
  if (grant.kind === "project") {
    if (!isProjectName(grant.project)) refuse("project");
    if (!isProjectRole(grant.role)) refuse("role");
    return subjectOf(grant);
  }
  if (!isGlobalRole(grant.role)) refuse("role");
  if (grant.role === CONNECTOR_ROLE) refuse("connector_role");
  return grant.role;
};

/**
 * The subject Argo CD gives `grant`'s role: the global role's own name, or
 * `proj:<project>:<role>` for a project role.
 */
const subjectOf = (grant: Grant): string =>
  grant.kind === "project" ? `proj:${grant.project}:${grant.role}` : grant.role;

/**
 * The `g` line that gives `email` the role, as P0 writes it:
 * `g, <email>, role:<name>` or `g, <email>, proj:<project>:<role>`, the email
 * in lower case. Each field is held to a strict pattern, so the line is one
 * line of three fields; the connector's own role is refused. Throws a
 * {@link PolicyLineError}, and nothing else.
 */
export const buildLine = (email: string, grant: Grant): P0Line =>
  `g, ${checkedEmail(email)}, ${checkedRole(grant)}` as P0Line;

/** The grant a P0 line's third field names. */
const grantOf = (subject: string): Grant => {
  const project = /^proj:([^:]*):([^:]*)$/.exec(subject);
  return project
    ? { kind: "project", project: project[1] ?? "", role: project[2] ?? "" }
    : { kind: "global", role: subject };
};

/**
 * What a line says, if it is one P0 writes, spelled exactly as
 * {@link buildLine} spells it; `undefined` for any other line.
 */
export const parseP0Line = (
  text: string
): { email: string; grant: Grant } | undefined => {
  const fields = text.split(", ");
  if (fields.length !== 3 || fields[0] !== "g") return undefined;
  const [, email = "", role = ""] = fields;
  const grant = grantOf(role);
  try {
    return buildLine(email, grant) === text ? { email, grant } : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Go's `unicode.IsSpace`, which Argo CD trims lines and leading field space
 * by. Not JavaScript's `\s`, which also has U+FEFF and lacks U+0085.
 */
const GO_SPACE =
  /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;
const GO_TRIM = new RegExp(`^${GO_SPACE.source}+|${GO_SPACE.source}+$`, "g");

/** `text` without the space Go's `strings.TrimSpace` trims. */
export const goTrim = (text: string) => text.replace(GO_TRIM, "");

/** Whether `text`, as Argo CD reads a line, is `line`. */
const isLine = (text: string, line: P0Line) => goTrim(text) === line;

/**
 * `policy.p0.csv`'s value with `line` in it. Unchanged when the line is
 * there already; otherwise it goes at the end, on a line of its own.
 */
export const addLine = (value: string | undefined, line: P0Line): string => {
  const current = value ?? "";
  if (current.split("\n").some((text) => isLine(text, line))) return current;
  const separator = current === "" || current.endsWith("\n") ? "" : "\n";
  return `${current}${separator}${line}\n`;
};

/**
 * `policy.p0.csv`'s value without `line`. Only a line that is exactly
 * `line`, but for the space Argo CD trims around it, is removed: every other
 * line, even one that grants the same, stays as it was. Unchanged when the
 * line isn't there.
 */
export const removeLine = (value: string | undefined, line: P0Line): string =>
  (value ?? "")
    .split("\n")
    .filter((text) => !isLine(text, line))
    .join("\n");

/**
 * One policy line's fields, read as Go's CSV reader reads it with
 * `TrimLeadingSpace`, which is how Argo CD reads it: the space before a field
 * is dropped, and nothing else is. A field may be quoted, with `""` for a
 * quote in it, and is then read as it is between the quotes. `undefined` for
 * a line Go refuses: a quote in an unquoted field, or anything but a comma
 * after a closing quote.
 */
export const parseCsvLine = (line: string): string[] | undefined => {
  const fields: string[] = [];
  let at = 0;
  for (;;) {
    while (GO_SPACE.test(line[at] ?? "")) at++;
    if (line[at] === '"') {
      let field = "";
      at++;
      for (;;) {
        const close = line.indexOf('"', at);
        if (close === -1) return undefined;
        field += line.slice(at, close);
        at = close + 1;
        if (line[at] !== '"') break;
        field += '"';
        at++;
      }
      fields.push(field);
      if (at === line.length) return fields;
      if (line[at] !== ",") return undefined;
      at++;
      continue;
    }
    const comma = line.indexOf(",", at);
    const field = line.slice(at, comma === -1 ? undefined : comma);
    if (field.includes('"')) return undefined;
    fields.push(field);
    if (comma === -1) return fields;
    at = comma + 1;
  }
};

/**
 * The keys of `argocd-rbac-cm` Argo CD reads policy from, in the order it
 * reads them: `policy.csv`, then every other `policy.*.csv` key in order.
 */
export const policyKeys = (data: Record<string, string>): string[] => [
  ...("policy.csv" in data ? ["policy.csv"] : []),
  ...Object.keys(data)
    .filter(
      (key) =>
        key !== "policy.csv" &&
        key.startsWith("policy.") &&
        key.endsWith(".csv")
    )
    .sort(),
];

/**
 * The OIDC scopes `scopes` names, which Argo CD matches `g` lines' subjects
 * against. `scopes` is a YAML flow list, such as `[groups, email]`, its items
 * quoted or not; absent or blank, it is `[groups]`. `undefined` for a value
 * that isn't such a list.
 */
export const parseScopes = (
  value: string | undefined
): string[] | undefined => {
  const trimmed = value?.trim() ?? "";
  if (trimmed === "") return ["groups"];
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return undefined;
  const inner = trimmed.slice(1, -1);
  if (inner.trim() === "") return [];
  const scopes: string[] = [];
  for (const raw of inner.split(",")) {
    const item = raw.trim();
    const quote = item[0];
    if (quote === "'" || quote === '"') {
      if (item.length < 2 || !item.endsWith(quote)) return undefined;
      const scope = item.slice(1, -1);
      if (scope.includes(quote)) return undefined;
      scopes.push(scope);
    } else {
      if (item === "" || /["'[\]{}]/.test(item)) return undefined;
      scopes.push(item);
    }
  }
  return scopes;
};

/** `argocd-rbac-cm`'s policy, as {@link parsePolicy} reads it. */
export type RbacPolicy = {
  /** Each `g` line's subject, and the roles its lines give it. */
  inherits: ReadonlyMap<string, ReadonlySet<string>>;
  /** Every role a `p` line gives a permission to. */
  permitted: ReadonlySet<string>;
  /** `policy.default`: the role every user holds, if any. */
  defaultRole: string | undefined;
  /** `scopes`, as {@link parseScopes} reads it. */
  scopes: string[] | undefined;
  /**
   * Where a line is that Argo CD refuses, each as its key and its line
   * number from 1. Argo CD then enforces the policy it had before, which the
   * ConfigMap no longer shows, so nothing read here is sure.
   */
  refusedLines: { key: string; line: number }[];
  /** The AppProjects read with it, and their roles. */
  projects: readonly ArgoCdProject[];
};

/**
 * Reads `argocd-rbac-cm`'s `data`: the `g` and `p` lines of every
 * {@link policyKeys} key, `policy.default` and `scopes`. Each of `projects`'
 * roles counts as a `g` line from each of its groups to the role, as Argo CD
 * counts it.
 */
export const parsePolicy = (
  { data }: { data: Record<string, string> },
  projects: readonly ArgoCdProject[] = []
): RbacPolicy => {
  const inherits = new Map<string, Set<string>>();
  const permitted = new Set<string>();
  const refusedLines: { key: string; line: number }[] = [];
  const inherit = (subject: string, role: string) => {
    const roles = inherits.get(subject) ?? new Set();
    roles.add(role);
    inherits.set(subject, roles);
  };
  for (const project of projects) {
    for (const role of project.roles) {
      const subject = subjectOf({
        kind: "project",
        project: project.name,
        role: role.name,
      });
      for (const group of role.groups) inherit(group, subject);
    }
  }
  for (const key of policyKeys(data)) {
    for (const [index, raw] of (data[key] ?? "").split("\n").entries()) {
      const line = goTrim(raw);
      if (line === "" || line.startsWith("#")) continue;
      const fields = parseCsvLine(line);
      if (fields?.[0] === "g" && fields.length === 3) {
        const [, subject = "", role = ""] = fields;
        inherit(subject, role);
      } else if (fields?.[0] === "p" && fields.length === 6) {
        permitted.add(fields[1] ?? "");
      } else {
        refusedLines.push({ key, line: index + 1 });
      }
    }
  }
  const defaultRole = goTrim(data["policy.default"] ?? "");
  return {
    inherits,
    permitted,
    defaultRole: defaultRole === "" ? undefined : defaultRole,
    scopes: parseScopes(data.scopes),
    refusedLines,
    projects,
  };
};

/** Every role `subject` holds through `g` lines, itself included. */
const reachable = (policy: RbacPolicy, subject: string): Set<string> => {
  const seen = new Set([subject]);
  const unvisited = [subject];
  for (let next = unvisited.pop(); next !== undefined; next = unvisited.pop()) {
    for (const role of policy.inherits.get(next) ?? []) {
      if (!seen.has(role)) {
        seen.add(role);
        unvisited.push(role);
      }
    }
  }
  return seen;
};

/**
 * Whether the user with `email` already holds exactly what `grant` gives:
 * through a `g` line for their email in any policy key, membership of the
 * project role's `groups`, `policy.default`, or a role any of those inherits
 * through `g` lines, cycles included. A role that holds more than `grant`'s
 * isn't counted. Nor is a line Argo CD refuses: see
 * {@link RbacPolicy.refusedLines}.
 *
 * It can't see the user's IdP groups. A `g` line whose subject is a group,
 * and an AppProject role's group, count only when the group's name is the
 * email itself, as it is when `scopes` has `email`.
 */
export const holds = (
  policy: RbacPolicy,
  email: string,
  grant: Grant
): boolean => {
  const target = subjectOf(grant);
  if (reachable(policy, email.toLowerCase()).has(target)) return true;
  return (
    policy.defaultRole !== undefined &&
    reachable(policy, policy.defaultRole).has(target)
  );
};
