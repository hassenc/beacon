#!/bin/sh
# Local candidate artifacts only. Does not publish or sign.
set -eu
cd "$(dirname "$0")/.."
git rev-parse --verify HEAD >/dev/null
if test -n "$(git status --porcelain)"; then
  echo "Commit reviewed changes before building release artifacts." >&2
  exit 1
fi
mkdir -p artifacts/release artifacts/tools
GOBIN="$PWD/artifacts/tools" go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0
cp LICENSE THIRD_PARTY_NOTICES.md artifacts/release/
for platform in linux/amd64 linux/arm64 darwin/arm64; do
  target_os=${platform%/*}
  target_arch=${platform#*/}
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "artifacts/release/beacon-${target_os}-${target_arch}" ./cmd/beacon
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" artifacts/tools/cyclonedx-gomod app -json -std -main cmd/beacon -output "artifacts/release/sbom-${target_os}-${target_arch}.cdx.json" .
done
python3 scripts/release-manifest.py
