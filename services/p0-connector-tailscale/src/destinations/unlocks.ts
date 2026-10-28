import { uniqBy } from "lodash-es";

import { attributeKeyFor } from "../accesses/posture/definition.ts";
import {
  isObject,
  posturesOf,
  section,
  strings,
} from "../tailscale/inventory.ts";
import type { UnlockedGrant, UnlockedSshRule, Unlocks } from "./definition.ts";

/**
 * What a posture unlocks: the customer's `grants` entries, legacy `acls`
 * entries and `ssh` rules that the attribute P0 sets for it opens, for the
 * approver to see. Tailscale lets any posture read any attribute, so that
 * is every entry gated by the posture itself or by another posture whose
 * assertions read the attribute. An entry is gated by its own `srcPosture`,
 * or, when that names no posture (missing, `null` or `[]`), by the file's
 * `defaultSrcPosture`. Read from the policy file as JSON, field names
 * matched without regard to case, as Tailscale matches them.
 */

type Json = Record<string, unknown>;

type Gated = {
  entry: Json;
  posture: string;
  fromDefault: boolean;
  /** The entry's other postures, which open it without the attribute. */
  alsoOpenedBy: string[];
};

/**
 * Whether `assertion` reads attribute `key` as a whole key, so
 * `custom:p0_web` and not `custom:p0_web2`.
 */
const readsAttribute = (assertion: string, key: string): boolean =>
  assertion.split(/[^A-Za-z0-9_:]+/).includes(key);

/**
 * The postures the attribute P0 sets for `posture` can satisfy: `posture`
 * itself, then each other posture whose assertions read that attribute, in
 * file order.
 */
const gatingPostures = (policy: Json, posture: string): string[] => {
  const key = attributeKeyFor(posture);
  const others = posturesOf(policy).filter(
    ({ name, assertions }) =>
      name !== posture && assertions.some((each) => readsAttribute(each, key))
  );
  return [posture, ...others.map(({ name }) => name)];
};

/**
 * The entries of section `name` that one of `postures` gates, each marked
 * with the first of them that does, and with the entry's other postures:
 * a device passing any one posture of the list reaches the entry, so those
 * open it without P0.
 */
const gated = (policy: Json, name: string, postures: string[]): Gated[] => {
  const entries = section(policy, name);
  if (!Array.isArray(entries)) return [];
  const defaults = strings(section(policy, "defaultSrcPosture"));
  return entries.filter(isObject).flatMap((entry): Gated[] => {
    const own = strings(section(entry, "srcPosture"));
    const fromDefault = own.length === 0;
    const named = fromDefault ? defaults : own;
    const posture = postures.find((each) => named.includes(each));
    const alsoOpenedBy = named.filter((each) => !postures.includes(each));
    return posture === undefined
      ? []
      : [{ entry, posture, fromDefault, alsoOpenedBy }];
  });
};

/**
 * The posture that gates an entry, whether the default posture names it,
 * and the postures that open it without P0.
 */
const marked = ({ posture, fromDefault, alsoOpenedBy }: Gated) => ({
  posture,
  ...(fromDefault ? { fromDefault: true } : {}),
  ...(alsoOpenedBy.length > 0 ? { alsoOpenedBy } : {}),
});

/** A grant as it is, with each capability's values. */
const fromGrant = (gate: Gated): UnlockedGrant => {
  const { entry } = gate;
  const ip = section(entry, "ip");
  const via = section(entry, "via");
  const app = section(entry, "app");
  return {
    src: strings(section(entry, "src")),
    dst: strings(section(entry, "dst")),
    ...(ip !== undefined ? { ip: strings(ip) } : {}),
    ...(via !== undefined ? { via: strings(via) } : {}),
    ...(isObject(app)
      ? {
          app: Object.fromEntries(
            Object.entries(app).map(([name, values]) => [
              name,
              Array.isArray(values) ? values : [],
            ])
          ),
        }
      : {}),
    ...marked(gate),
  };
};

/**
 * One `host:ports` of a legacy `acls` entry, split at the last `:` so an
 * IPv6 host keeps its own, with each port after the entry's `proto` when it
 * has one.
 */
const hostAndPorts =
  (proto: unknown) =>
  (each: string): { host: string; ip: string[] } => {
    const colon = each.lastIndexOf(":");
    const ports =
      colon < 0
        ? []
        : each
            .slice(colon + 1)
            .split(",")
            .filter(Boolean);
    return {
      host: colon < 0 ? each : each.slice(0, colon),
      ip: ports.map((port) =>
        typeof proto === "string" && proto !== "" ? `${proto}:${port}` : port
      ),
    };
  };

/**
 * A legacy `acls` entry in the grant shape: hosts that share their ports
 * become one entry, whose `ip` is those ports. Tailscale still takes the
 * legacy names `users` for `src` and `ports` for `dst` there.
 */
const fromAcl = (gate: Gated): UnlockedGrant[] => {
  const { entry } = gate;
  const src = strings(section(entry, "src") ?? section(entry, "users"));
  const dsts = strings(section(entry, "dst") ?? section(entry, "ports")).map(
    hostAndPorts(section(entry, "proto"))
  );
  const portsOf = ({ ip }: { ip: string[] }) => ip.join(",");
  return uniqBy(dsts, portsOf).map(({ ip }) => ({
    src,
    dst: dsts
      .filter((each) => portsOf(each) === ip.join(","))
      .map(({ host }) => host),
    ...(ip.length > 0 ? { ip } : {}),
    ...marked(gate),
  }));
};

/** An `ssh` rule: who, to where, as which users, and how. */
const fromSsh = (gate: Gated): UnlockedSshRule => {
  const { entry } = gate;
  const action = section(entry, "action");
  return {
    src: strings(section(entry, "src")),
    dst: strings(section(entry, "dst")),
    users: strings(section(entry, "users")),
    ...(typeof action === "string" ? { action } : {}),
    ...marked(gate),
  };
};

/**
 * What the attribute P0 sets for `posture` unlocks: `grants` then `acls`
 * entries, and `ssh` rules, each in file order and marked with the posture
 * that gates it.
 */
export const unlocksOf = (policy: Json, posture: string): Unlocks => {
  const postures = gatingPostures(policy, posture);
  return {
    grants: [
      ...gated(policy, "grants", postures).map(fromGrant),
      ...gated(policy, "acls", postures).flatMap(fromAcl),
    ],
    ssh: gated(policy, "ssh", postures).map(fromSsh),
  };
};
