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
    banner: {
      js: "import { createRequire } from 'module';const require = createRequire(import.meta.url);",
    },
    format: "esm",
    platform: "node",
    // `jsonc-parser`'s `main` is a UMD build whose `require("./impl/...")`
    // calls esbuild can't follow, so the bundle would keep them and the
    // Lambda, which has only `index.mjs`, would fail as it loads. Its ESM
    // build bundles whole.
    mainFields: ["module", "main"],
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
