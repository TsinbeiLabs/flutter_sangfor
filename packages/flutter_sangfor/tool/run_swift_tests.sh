#!/usr/bin/env bash
# Compiles and runs the pure-Swift aTrust core tests against the golden
# fixtures emitted by the Dart reference implementation.
#
# The native data plane that runs inside the iOS packet tunnel extension has
# to reproduce Dart's canonical JSON, HMAC signatures, and protocol frames byte
# for byte, so these fixtures are the contract between the two.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

fixtures="test/fixtures/native_atrust.json"
if [[ ! -f "$fixtures" ]]; then
  echo "missing $fixtures" >&2
  exit 2
fi

out="${TMPDIR:-/tmp}/sangfor_native_tests"
swiftc="${SWIFTC:-swiftc}"
sources=()
while IFS= read -r file; do sources+=("$file"); done < <(
  find ios/flutter_sangfor/Sources/SangforTunnelCore/Native -name '*.swift' | sort
)

echo "compiling ${#sources[@]} native sources + swift-tests/main.swift"
"$swiftc" -O -o "$out" "${sources[@]}" swift-tests/main.swift
"$out" "$fixtures"
