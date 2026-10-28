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
    // The SDK reads its WebAssembly core from disk next to its own files, so
    // it ships in node_modules instead of in the bundle.
    external: ["@1password/sdk", "@1password/sdk-core"],
    banner: {
      js: "import { createRequire } from 'module';const require = createRequire(import.meta.url);",
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
