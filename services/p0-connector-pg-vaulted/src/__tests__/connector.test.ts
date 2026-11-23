import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** The source files and packages that importing `entry` loads. */
const loadedBy = async (entry: string) => {
  const { metafile } = await build({
    entryPoints: [fileURLToPath(new URL(entry, import.meta.url))],
    absWorkingDir: fileURLToPath(new URL("../..", import.meta.url)),
    bundle: true,
    write: false,
    metafile: true,
    platform: "node",
    format: "esm",
    conditions: ["@p0security/development"],
    external: ["oracledb", "mysql", "tedious", "better-sqlite3", "sqlite3"],
    logLevel: "silent",
  });
  return Object.keys(metafile.inputs);
};

// `@p0security/connector-core` loads an AWS Lambda client of its own, so the
// SDK as a whole is not refused here: only what this service adds is.
const HANDLERS_AND_CLIENTS =
  /(^src\/(.*\/)?handler\.ts$)|(^src\/(manager|router|index)\.ts$)|(^src\/postgres\/)|(node_modules\/(knex|pg|aws-ssl-profiles|@aws-sdk\/client-secrets-manager)\/)|(secret-manager-client\/)/;

describe("the contract the control plane imports", () => {
  it("loads the schemas, and no handler, database driver or secret manager client", async () => {
    const loaded = await loadedBy("../connector.ts");

    expect(loaded).toEqual(
      expect.arrayContaining([
        "src/connector.ts",
        "src/context.ts",
        "src/install/definition.ts",
        "src/accesses/role/definition.ts",
      ])
    );
    expect(loaded.filter((path) => HANDLERS_AND_CLIENTS.test(path))).toEqual(
      []
    );
  });
});
