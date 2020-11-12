#!/bin/sh

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
REQUIRE_BRANCH='master'
CURRENT_BRANCH="$(git symbolic-ref --short HEAD)"

if [[ "$CURRENT_BRANCH" != "$REQUIRE_BRANCH" ]]; then
  echo "Please \`git checkout $REQUIRE_BRANCH\` to run $SCRIPT_NAME (cannot run from current branch $CURRENT_BRANCH)."
  exit 1
fi

if [[ "$(git diff --stat)" != '' ]]; then
  echo 'Please commit or discard your changes before creating a new release.'
  exit 1
fi

echo "===  Publishing boring-sys... ==="
(cd boring-sys && cargo publish)
sleep 20

echo "===  Publishing boring... ==="
(cd boring && cargo publish)
sleep 20

echo "===  Publishing tokio-boring... ==="
(cd tokio-boring && cargo publish)
sleep 20

echo "===  Publishing hyper-boring... ==="
(cd hyper-boring && cargo publish)
sleep 20