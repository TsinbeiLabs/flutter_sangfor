# Compiles and runs the pure-Swift aTrust core tests against the golden
# fixtures emitted by the Dart reference implementation.
#
# Windows equivalent of tool/run_swift_tests.sh. Set SWIFTC to override the
# compiler path (defaults to the first swiftc.exe on PATH).
$ErrorActionPreference = 'Stop'

$packageRoot = Split-Path -Parent $PSScriptRoot
Set-Location $packageRoot

$fixtures = Join-Path $packageRoot 'test/fixtures/native_atrust.json'
if (-not (Test-Path $fixtures)) {
  Write-Error "missing $fixtures"
  exit 2
}

$swiftc = if ($env:SWIFTC) { $env:SWIFTC } else { 'swiftc' }
$output = Join-Path $env:TEMP 'sangfor_native_tests.exe'

$sources = @(Get-ChildItem 'ios/flutter_sangfor/Sources/SangforTunnelCore/Native' -Filter *.swift |
  ForEach-Object { $_.FullName })
$sources += (Join-Path $packageRoot 'swift-tests/main.swift')

Write-Host "compiling $($sources.Count) Swift sources with $swiftc"
& $swiftc -O -o $output @sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $output $fixtures
exit $LASTEXITCODE
