#!/usr/bin/env bash
# Build the Scrutiny oracle from a pinned commit of the Starosdev fork.
# The fork's code is not modified: we only drop oracle/main.go into a new
# directory of its module and build it.
#
# Usage: oracle/build.sh WORKDIR   -> produces WORKDIR/scrutiny-oracle(.exe)
set -euo pipefail

FORK_URL=https://github.com/Starosdev/scrutiny.git
FORK_COMMIT=de9f016f09871b549b00a38e8a2eb36b7a153287   # master, 2026-11-11

here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: build.sh WORKDIR}"
src="$work/scrutiny-src"

if [ ! -d "$src/.git" ]; then
  git clone -q "$FORK_URL" "$src"
fi
git -C "$src" fetch -q origin "$FORK_COMMIT" 2>/dev/null || true
git -C "$src" checkout -q "$FORK_COMMIT"

# Refuse to build on a modified fork tree (apart from our own directory).
if [ -n "$(git -C "$src" status --porcelain --untracked-files=no)" ]; then
  echo "fork checkout has local modifications, aborting" >&2
  exit 1
fi

mkdir -p "$src/cmd/scrutiny-oracle"
cp "$here/main.go" "$src/cmd/scrutiny-oracle/main.go"
(cd "$src" && go build -o "$work/scrutiny-oracle$( [ "${OS:-}" = Windows_NT ] && echo .exe )" ./cmd/scrutiny-oracle)
echo "built $work/scrutiny-oracle (fork $FORK_COMMIT)"
