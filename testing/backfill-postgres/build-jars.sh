#!/usr/bin/env bash
# Builds two app-authenticator jars for the before/after functional check:
#   jars/app-authenticator-pre-index.jar  - last commit before AppAuthCredentialIndex existed
#   jars/app-authenticator-with-index.jar - the ref under test (defaults to HEAD)
#
# Both commits produce a jar with the same finalName (project version isn't bumped
# between them), so each build happens in its own git worktree and gets copied out
# under a distinct name - building in place and overwriting target/ would leave you
# unable to tell the two jars apart.
set -euo pipefail

PRE_INDEX_REF="${1:-1a74600}"
WITH_INDEX_REF="${2:-HEAD}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JARS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/jars"
mkdir -p "$JARS_DIR"

build_ref() {
	local ref="$1" out_name="$2"
	local worktree
	worktree="$(mktemp -d)"

	echo "==> Building app-authenticator @ $ref"
	git -C "$REPO_ROOT" worktree add --detach "$worktree" "$ref" >/dev/null
	trap "git -C '$REPO_ROOT' worktree remove --force '$worktree' >/dev/null 2>&1 || true" RETURN

	(cd "$worktree" && mvn -q -pl app-authenticator -am package -DskipTests)

	local jar
	jar="$(find "$worktree/app-authenticator/target" -maxdepth 1 -name '*.jar' ! -name 'original-*' | head -1)"
	if [ -z "$jar" ]; then
		echo "No jar found in $worktree/app-authenticator/target" >&2
		exit 1
	fi
	cp "$jar" "$JARS_DIR/$out_name"
	echo "==> $out_name ready ($(basename "$jar") @ $ref)"

	git -C "$REPO_ROOT" worktree remove --force "$worktree" >/dev/null 2>&1 || true
	trap - RETURN
}

build_ref "$PRE_INDEX_REF" "app-authenticator-pre-index.jar"
build_ref "$WITH_INDEX_REF" "app-authenticator-with-index.jar"

echo
echo "Done. To start with the pre-index behavior:"
echo "  cp jars/app-authenticator-pre-index.jar jars/active.jar"
echo "To switch to the with-index behavior later:"
echo "  cp jars/app-authenticator-with-index.jar jars/active.jar"
