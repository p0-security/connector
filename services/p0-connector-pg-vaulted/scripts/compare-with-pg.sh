#!/bin/sh
# Prints how each file this service copied from p0-connector-pg differs from
# its original, so a review only has to read the differences. Run it from
# anywhere in the repository.
set -eu

root="$(git rev-parse --show-toplevel)/services"
copied="
accesses/common/definition.ts
accesses/common/handler.ts
accesses/role/definition.ts
accesses/role/handler.ts
clouds/aws-rds.ts
clouds/index.ts
clouds/localdev.ts
dbclient.ts
sql/identifier.ts
sql/__tests__/identifier.test.ts
__tests__/delete-user.test.ts
__tests__/role.test.ts
__tests__/setup.ts
__tests__/user-namespace.test.ts
"

same=0
changed=0
for file in $copied; do
  if git diff --no-index --quiet -- "$root/p0-connector-pg/src/$file" "$root/p0-connector-pg-vaulted/src/$file"; then
    same=$((same + 1))
    echo "same     $file"
  else
    changed=$((changed + 1))
    echo "changed  $file"
  fi
done
echo
echo "$same files are the same as in p0-connector-pg, $changed differ."

for file in $copied; do
  git --no-pager diff --no-index --stat=200 -p -- \
    "$root/p0-connector-pg/src/$file" "$root/p0-connector-pg-vaulted/src/$file" || true
done
