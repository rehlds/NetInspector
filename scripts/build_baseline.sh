#!/usr/bin/env bash
# Builds the recorder the way the oldest supported toolchain setup does: 32-bit, the
# pre-C++11 libstdc++ string ABI, no sized deallocation, no RTTI or exceptions, warnings
# as errors. Then checks its symbol versions against the baseline.

set -euo pipefail

cd "$(dirname "$0")/.."
output="build/baseline"
mkdir -p "$output/obj"

flags=(
	-m32 -std=c++14 -fPIC -O2
	-Wall -Wextra -Werror
	-fno-rtti -fno-exceptions -fno-sized-deallocation
	-D_GLIBCXX_USE_CXX11_ABI=0
	-Iinclude -Isrc
)

objects=()
while IFS= read -r source; do
	object="$output/obj/$(echo "${source%.cpp}" | tr / _).o"
	g++ "${flags[@]}" -c "$source" -o "$object"
	objects+=("$object")
done < <(find src -name '*.cpp' -not -path '*/platform/windows/*' | sort)

g++ -m32 -shared -o "$output/libnetinspector.so" "${objects[@]}" -lpthread
scripts/check_abi.sh "$output/libnetinspector.so"
