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
matcher_cases="test/fixtures/route_matcher_cases.json"
if [[ ! -f "$matcher_cases" ]]; then
  echo "missing $matcher_cases" >&2
  exit 2
fi
"$out" "$fixtures" "$matcher_cases"

# The direct stream and the proxy server are Network.framework code, so they have their own binary:
# it needs a real loopback listener and is not part of the portable sources.
network_out="${TMPDIR:-/tmp}/sangfor_network_tests"
"$swiftc" -O -o "$network_out" "${sources[@]}" \
  ios/flutter_sangfor/Sources/SangforTunnelCore/SangforDirectStream.swift \
  ios/flutter_sangfor/Sources/SangforTunnelCore/SangforProxyServer.swift \
  swift-tests/network/main.swift
"$network_out"
