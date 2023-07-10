#!/usr/bin/env bash

set -euo pipefail

git apply -v --whitespace=fix ../../patches/boring-pq.patch
