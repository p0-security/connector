#!/bin/sh
# Starts or removes the PostgreSQL servers of the integration tests: one per
# version, each on 127.0.0.1 at port 543<version>, with a self-signed
# certificate so that the shipped driver's TLS check has something to refuse.
set -eu

VERSIONS="14 16"

name() {
  echo "p0-pg-vaulted-it-$1"
}

case "${1:-}" in
  up)
    for version in $VERSIONS; do
      docker run --detach --name "$(name "$version")" \
        --env POSTGRES_PASSWORD=postgres \
        --publish "127.0.0.1:543${version}:5432" \
        "postgres:${version}" \
        -c ssl=on \
        -c ssl_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem \
        -c ssl_key_file=/etc/ssl/private/ssl-cert-snakeoil.key >/dev/null
    done
    for version in $VERSIONS; do
      # Over TCP, which the server opens only once its setup has finished.
      until docker exec "$(name "$version")" \
        pg_isready --quiet --host 127.0.0.1 --username postgres; do
        sleep 1
      done
      echo "PostgreSQL ${version} is ready on 127.0.0.1:543${version}"
    done
    ;;
  down)
    for version in $VERSIONS; do
      docker rm --force "$(name "$version")" >/dev/null 2>&1 || true
    done
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 1
    ;;
esac
