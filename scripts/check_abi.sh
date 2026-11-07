#!/usr/bin/env bash
# Fails if a binary needs newer glibc or libstdc++ symbol versions than the baseline the
# recorder supports: scripts/check_abi.sh <binary>...

set -euo pipefail

declare -A BASELINE=(
	[GLIBC]=2.11
	[GLIBCXX]=3.4.15
	[CXXABI]=1.3.5
)

newest_version()
{
	readelf --dyn-syms --wide "$1" | sed -n "s/.*@$2_\([0-9.]*\).*/\1/p" | sort -u -V | tail -1
}

failed=0
for binary in "$@"; do
	for library in "${!BASELINE[@]}"; do
		limit="${BASELINE[$library]}"
		version="$(newest_version "$binary" "$library")"

		if [[ -z "$version" ]]; then
			echo "$binary: no $library symbols"
		elif [[ "$(printf '%s\n%s\n' "$version" "$limit" | sort -V | tail -1)" != "$limit" ]]; then
			echo "$binary: needs ${library}_$version, the baseline is ${library}_$limit"
			failed=1
		else
			echo "$binary: ${library}_$version within ${library}_$limit"
		fi
	done
done

exit $failed
