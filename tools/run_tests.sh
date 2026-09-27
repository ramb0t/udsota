#!/bin/sh
# Builds and runs the host tests: configure, build, ctest. Usage: tools/run_tests.sh [build-dir] [cmake args...]
# The build directory defaults to ./build at the repository root.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
build=${1:-"$root/build"}
[ $# -gt 0 ] && shift
cmake -S "$root" -B "$build" "$@"
cmake --build "$build" -j
ctest --test-dir "$build" --output-on-failure
