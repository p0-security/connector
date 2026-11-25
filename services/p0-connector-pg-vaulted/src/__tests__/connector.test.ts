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
    // copy of `external` in esbuild.mjs
    external: [
      "oracledb",
      "mysql",
      "tedious",
      "better-sqlite3",
      "sqlite3",
      "pg-query-stream",
      "mariadb",
    ],
    logLevel: "silent",
  });
  return Object.keys(metafile.inputs);
};

const HANDLERS_AND_CLIENTS =
  /(^src\/(.*\/)?handler\.ts$)|(^src\/(manager|router|index|dbclient)\.ts$)|(^src\/(clouds|postgres)\/)|(node_modules\/(knex|pg|aws-ssl-profiles|@aws-sdk\/client-secrets-manager)\/)|(secret-manager-client\/)/;

describe("the contract the control plane imports", () => {
  it("loads the schemas, and no handler, database driver or secret manager client", async () => {
    const loaded = await loadedBy("../connector.ts");

    expect(loaded).toEqual(
      expect.arrayContaining([
        "src/connector.ts",
        "src/context.ts",
        "src/install/definition.ts",
      ])
    );
    expect(loaded.filter((path) => HANDLERS_AND_CLIENTS.test(path))).toEqual(
      []
    );
  });

  it("would catch the handler loading the secret manager client", async () => {
    const loaded = await loadedBy("../index.ts");

    expect(loaded.filter((path) => HANDLERS_AND_CLIENTS.test(path))).toEqual(
      expect.arrayContaining(["src/manager.ts", "src/dbclient.ts"])
    );
  });
});
