import { ConnectorError } from "@p0security/connector";
import { describe, expect, it } from "vitest";

import { closeOverParents, toLevelPermissions } from "../roles.ts";
import { type Random, fileSeed, forAll } from "./generate.ts";

/**
 * The permissions and parents come from the Looker instance, so any graph is
 * possible: loops, parents it doesn't list, empty names. The closure always
 * ends, and is exactly what a plain search from the wanted permissions
 * reaches.
 */

const SEED = fileSeed();
const RUNS = 2000;

const NAMES = ["a", "b", "c", "d", "e", "f", "develop", "explore", ""];

type Graph = {
  parents: Map<string, string | null>;
  wanted: string[];
};

const anyGraph = (random: Random): Graph => {
  const parents = new Map<string, string | null>();
  for (const name of NAMES) {
    if (random.chance(0.7)) {
      parents.set(name, random.chance(0.3) ? null : random.pick(NAMES));
    }
  }
  const wanted = Array.from({ length: random.int(0, 4) }, () =>
    random.pick(NAMES)
  );
  return { parents, wanted };
};

/** A search over the parent links, written another way. */
const reachable = ({ parents, wanted }: Graph) => {
  const seen = new Set<string>();
  const queue = wanted.filter(Boolean);
  while (queue.length > 0) {
    const next = queue.shift() as string;
    if (seen.has(next)) continue;
    seen.add(next);
    const parent = parents.get(next);
    if (parent) queue.push(parent);
  }
  return {
    permissions: [...seen].filter((name) => parents.has(name)).sort(),
    missing: [...seen].filter((name) => !parents.has(name)).sort(),
  };
};

describe("closeOverParents, on generated permission graphs", () => {
  it("is exactly what the parent links reach", async () => {
    const counts = await forAll(SEED, RUNS, anyGraph, (graph) => {
      const closed = closeOverParents(graph.wanted, graph.parents);
      expect(closed).toEqual(reachable(graph));
      return closed.missing.length > 0
        ? "missing"
        : closed.permissions.length > 0
          ? "closed"
          : "empty";
    });

    expect(Object.keys(counts).sort()).toEqual(["closed", "empty", "missing"]);
  });

  it("never lets toLevelPermissions return a refused permission, or throw anything but a ConnectorError", async () => {
    const LOOKER_NAMES = [
      "access_data",
      "see_looks",
      "explore",
      "develop",
      "manage_models",
      "see_sql",
    ];
    const counts = await forAll(
      SEED,
      RUNS,
      (random) => {
        const parents = new Map<string, string | null>();
        for (const name of [
          ...LOOKER_NAMES,
          "see_user_dashboards",
          "see_lookml_dashboards",
          "save_content",
          "save_looks",
          "save_dashboards",
        ]) {
          if (random.chance(0.9)) {
            parents.set(
              name,
              random.chance(0.5) ? null : random.pick(LOOKER_NAMES)
            );
          }
        }
        return { parents, level: random.pick(["read", "edit"] as const) };
      },
      ({ parents, level }) => {
        try {
          const permissions = toLevelPermissions(level, parents);
          expect(permissions).not.toContain("develop");
          expect(permissions).not.toContain("manage_models");
          return "granted";
        } catch (error) {
          expect(error).toBeInstanceOf(ConnectorError);
          return "refused";
        }
      }
    );

    expect(Object.keys(counts).sort()).toEqual(["granted", "refused"]);
  });
});
