#!/usr/bin/env node
import esbuild from "esbuild";

esbuild
  .build({
    entryPoints: ["./src/index.ts"],
    // Bundling and minifying keep the Cloud Run image small.
    bundle: true,
    minify: true,
    sourcemap: true,
    banner: {
      js: "import { createRequire } from 'module';const require = createRequire(import.meta.url);",
    },
    format: "esm",
    platform: "node",
    // Keep this in sync with the Node version in the Dockerfile.
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
