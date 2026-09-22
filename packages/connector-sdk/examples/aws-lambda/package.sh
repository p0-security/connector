#!/usr/bin/env bash
# Builds this example and packages it as connector-lambda.zip, ready to deploy
# as an AWS Lambda function's code (aws_lambda_function.filename / the
# console's "Upload from .zip file").
#
# dist/ stays nested (not flattened to the zip root): src/index.ts locates
# package.json via "../package.json", which only resolves correctly when the
# compiled index.js keeps dist/'s position one level below the package root,
# same as this example's compiled layout during development. The Lambda
# handler is configured as "dist/index.handler" to match.
set -euo pipefail
cd "$(dirname "$0")"

rm -rf dist build connector-lambda.zip
if [ -f package-lock.json ]; then npm ci; else npm install; fi
npm run build

mkdir -p build
cp -r dist build/dist
cp package.json build/package.json
[ -f package-lock.json ] && cp package-lock.json build/package-lock.json

(
  cd build
  if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi
  rm -f package-lock.json
  zip -rq ../connector-lambda.zip .
)

rm -rf build
echo "Wrote $(pwd)/connector-lambda.zip"
