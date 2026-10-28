#!/usr/bin/env node
import esbuild from "esbuild";

esbuild
  .build({
    entryPoints: ["./src/index.ts"],
    // Bundling + minification is the primary reason for adding esbuild, as it cuts
    // down the size of the Lambda function significantly.
    bundle: true,
    minify: true,
    sourcemap: true,
    // snowflake-sdk reads `__dirname` when it connects, which an ES module
    // bundle doesn't define, so the Lambda image would fail every sign-in.
    banner: {
      js: "import { createRequire } from 'module';import { fileURLToPath as __p0FileUrlToPath } from 'url';import { dirname as __p0Dirname } from 'path';const require = createRequire(import.meta.url);const __filename = __p0FileUrlToPath(import.meta.url);const __dirname = __p0Dirname(__filename);",
    },
    format: "esm",
    platform: "node",
    // Keep this in sync w/ dockerfile and Lambda runtime!
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
