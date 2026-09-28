#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
set -a
. ./.env
set +a
export BEACON_TEST_DATABASE_URL="postgres://beacon:${POSTGRES_PASSWORD}@127.0.0.1:55438/beacon?sslmode=disable"
go test -race -count=1 ./...
go vet ./...
