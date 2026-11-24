#!/usr/bin/env node
import esbuild from "esbuild";

esbuild
  .build({
    entryPoints: ["./src/index.ts"],
    // Bundling and minifying cut the Lambda's size a lot, which is why the
    // connector is built with esbuild.
    bundle: true,
    minify: true,
    sourcemap: true,
    // copy of `external` in services/p0-connector-pg/esbuild.mjs: knex's
    // drivers for other databases, which it requires only when asked for.
    external: [
      "oracledb",
      "mysql",
      "tedious",
      "better-sqlite3",
      "sqlite3",
      "pg-query-stream",
      "mariadb",
    ],
    banner: {
      js: "import { createRequire } from 'module';const require = createRequire(import.meta.url);",
    },
    format: "esm",
    platform: "node",
    // Keep this in sync with the Dockerfile and the Lambda runtime.
    target: "es2022",
    outfile: "dist/index.mjs",
  })
  .then(() => {
    console.log("Bundling succeeded.");
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
