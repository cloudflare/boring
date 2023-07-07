#!/usr/bin/env bash

set -euo pipefail

git apply -v --whitespace=fix ../../../patches/rpk-patch/include/*/*.patch ../../../patches/rpk-patch/ssl/*.patch
