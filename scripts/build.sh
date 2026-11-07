#!/usr/bin/env bash
# Configures, builds and tests one preset: scripts/build.sh [linux-gcc | linux-clang | linux-sanitizers]

set -euo pipefail

preset="${1:-linux-gcc}"
cd "$(dirname "$0")/.."

cmake --preset "$preset"
cmake --build --preset "$preset" --parallel
ctest --preset "$preset"
