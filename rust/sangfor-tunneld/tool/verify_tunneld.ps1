<#
.SYNOPSIS
  Verifies sangfor-tunneld on this machine, in two stages.

.DESCRIPTION
  Stage 1 (preflight, the default) answers "could this ever work here" without
  touching the network configuration: it checks elevation, the signed wintun
  driver, the daemon binary, and that the daemon itself runs and serves its
  control protocol against an in-memory device.

  Stage 2 (-Plan) runs a real tunnel against a real gateway. It needs a session
  plan exported from the app, elevation, and the driver staged. It configures a
  wintun adapter, waits for the gateway to assign a virtual IP, reports what the
  tunnel is doing, optionally probes a resource through it, and tears down.

  Nothing here is destructive: routes are installed with store=active, so they
  do not survive a reboot, and the adapter is removed when the daemon exits.

.PARAMETER Preflight
  Run stage 1 only. This is the default.

.PARAMETER Plan
  Path to a session plan JSON, exported from the app. Enables stage 2.

.PARAMETER Config
  Path to a host configuration JSON. Omit it to use the defaults plus the
  parameters below.

.PARAMETER Routes
  CIDR blocks to route through the tunnel, for example 10.0.0.0/8. Required for
  stage 2 unless -Config supplies them: the daemon installs what it is given and
  deliberately does not decide for itself, because which destinations belong in
  the tunnel depends on the user's route policy in the app.

.PARAMETER Dns
  DNS servers to set on the adapter.

.PARAMETER Probe
  A host:port or URL to try through the tunnel once it is up. The probe runs
  outside the tunnel's own process, so a success means the operating system
  really is routing through the adapter.

.PARAMETER TestAdapter
  Also create and remove a throwaway wintun adapter during preflight. Proves the
  driver installs, which the binary check alone does not. Requires elevation and
  briefly adds a network adapter.

.PARAMETER Daemon
  Path to the daemon. Defaults to the release build in the workspace, then to a
  copy beside this script.

.PARAMETER WintunDll
  Path to wintun.dll. Defaults to the copy staged beside the daemon.

.EXAMPLE
  ./verify_tunneld.ps1

.EXAMPLE
  ./verify_tunneld.ps1 -Plan plan.json -Routes 10.0.0.0/8 -Probe https://portal.example.edu/
#>
[CmdletBinding()]
param(
  [switch]$Preflight,
  [string]$Plan,
  [string]$Config,
  [string[]]$Routes = @(),
  [string[]]$Dns = @(),
  [string]$Probe,
  [switch]$TestAdapter,
  [string]$Daemon,
  [string]$WintunDll,
  [int]$SettleSeconds = 45
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Warnings = 0

function Write-Step { param([string]$Message) Write-Host "`n== $Message" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host "  ok    $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "  warn  $Message" -ForegroundColor Yellow; $script:Warnings++ }
function Write-Bad { param([string]$Message) Write-Host "  FAIL  $Message" -ForegroundColor Red; $script:Failures++ }
function Write-Info { param([string]$Message) Write-Host "        $Message" -ForegroundColor DarkGray }

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Daemon {
  if ($Daemon) {
    $resolved = Resolve-Path $Daemon -ErrorAction SilentlyContinue
    if ($resolved) { return $resolved.Path }
    Write-Bad "-Daemon '$Daemon' does not exist"
    return $null
  }
  # tool -> sangfor-tunneld -> rust -> repository root
  $rustRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
  $candidates = @()
  # A global CARGO_TARGET_DIR moves the build output out of the workspace, which
  # is common on developer machines and would otherwise make this look like a
  # missing build.
  if ($env:CARGO_TARGET_DIR) {
    $candidates += Join-Path $env:CARGO_TARGET_DIR 'release\sangfor-tunneld.exe'
    $candidates += Join-Path $env:CARGO_TARGET_DIR 'debug\sangfor-tunneld.exe'
  }
  $candidates += Join-Path $rustRoot 'target\release\sangfor-tunneld.exe'
  $candidates += Join-Path $rustRoot 'target\debug\sangfor-tunneld.exe'
  $candidates += Join-Path $PSScriptRoot 'sangfor-tunneld.exe'
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

# ---------------------------------------------------------------------------
# Stage 1: preflight
# ---------------------------------------------------------------------------

function Invoke-Preflight {
  param([string]$DaemonPath)

  Write-Step 'Privileges'
  if (Test-Admin) {
    Write-Ok 'running elevated; a wintun adapter can be created'
  }
  else {
    Write-Warn 'not elevated. Preflight still runs, but a real tunnel needs ' +
      'elevation -- which is exactly what running the daemon as a service ' +
      'removes from the app.'
  }

  Write-Step 'Driver'
  $dll = $WintunDll
  if (-not $dll) {
    $dll = Join-Path (Split-Path -Parent $DaemonPath) 'wintun.dll'
  }
  if (Test-Path -LiteralPath $dll) {
    $version = (Get-Item -LiteralPath $dll).VersionInfo.FileVersion
    Write-Ok "wintun.dll found at $dll (version $version)"
    Write-Info 'It must be the signed DLL from https://www.wintun.net/; a self-built copy will not load.'
  }
  else {
    # Only stage 2 opens a real adapter. Failing preflight over a missing driver
    # would hide the checks that do not need one.
    if ($Plan) {
      Write-Bad "no wintun.dll at $dll, and a real tunnel needs it"
    }
    else {
      Write-Warn "no wintun.dll at $dll (only needed for a real tunnel)"
    }
    Write-Info 'Run the app''s app/scripts/stage_wintun.ps1, which pins the archive SHA-256.'
  }

  Write-Step 'Daemon'
  # Capture the whole stream before looking at $LASTEXITCODE: piping a native
  # command into `Select-Object -First 1` stops the pipeline early and can kill
  # the process before it sets an exit code at all.
  $helpOutput = & $DaemonPath --help 2>&1
  $helpExit = $LASTEXITCODE
  if ($helpExit -eq 0) {
    Write-Ok "$DaemonPath runs ($($helpOutput | Select-Object -First 1))"
  }
  else {
    Write-Bad "$DaemonPath --help exited $helpExit"
    Write-Info ($helpOutput -join "`n")
    return
  }

  Write-Step 'Dry run (in-memory device, no privileges needed)'
  $scratch = Join-Path ([IO.Path]::GetTempPath()) "sangfor-verify-$PID"
  New-Item -ItemType Directory -Force -Path $scratch | Out-Null
  try {
    $planPath = Join-Path $scratch 'plan.json'
    # A syntactically valid plan naming a documentation-range node. The tunnel
    # comes up and then fails to connect, which is the point: this stage checks
    # the process, not the gateway.
    @'
{"schemaVersion":1,"sid":"preflight","deviceId":"dev","connectionId":"conn",
 "username":"user","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
 "lang":"en","processName":"tunneld","processPath":"C:\\tunneld.exe",
 "processPlatform":"windows","nodes":{"major":["203.0.113.9:441"]},
 "majorNodeGroup":"major","routes":[],"dnsServers":[],"heartbeatSeconds":2}
'@ | Set-Content -LiteralPath $planPath -NoNewline

    $configPath = Join-Path $scratch 'host.json'
    @{
      device       = 'loopback'
      interface    = 'sangfor-preflight'
      controlPort  = 0
      controlToken = "preflight-$PID"
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $configPath -NoNewline

    $stderrPath = Join-Path $scratch 'daemon.log'
    $process = Start-Process -FilePath $DaemonPath `
      -ArgumentList '--dry-run', '--plan', $planPath, '--config', $configPath `
      -RedirectStandardError $stderrPath -RedirectStandardOutput (Join-Path $scratch 'out.txt') `
      -PassThru -NoNewWindow

    $port = Wait-ForControlPort -LogPath $stderrPath -TimeoutSeconds 20
    if ($null -eq $port) {
      Write-Bad 'the daemon never reported a control port'
      Write-Info (Get-Content -LiteralPath $stderrPath -Raw)
      return
    }
    Write-Ok "control socket listening on 127.0.0.1:$port"

    $ping = Send-ControlRequest -Port $port -Request @{ cmd = 'ping' }
    if ($ping.ok) {
      Write-Ok 'ping answered'
    }
    else {
      Write-Bad "ping was refused: $($ping | ConvertTo-Json -Compress)"
    }

    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = "preflight-$PID" }
    if ($status.ok) {
      Write-Ok 'status answered'
      Write-Info ($status.data | ConvertTo-Json -Compress)
    }
    else {
      Write-Bad "status was refused: $($status | ConvertTo-Json -Compress)"
    }

    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status' }
    if (-not $status.ok) {
      Write-Ok 'status without the token was refused, as it should be'
    }
    else {
      Write-Bad 'status succeeded without a token; the control socket is open to any local process'
    }

    Send-ControlRequest -Port $port -Request @{ cmd = 'stop'; token = "preflight-$PID" } | Out-Null
    if ($process.WaitForExit(10000)) {
      if ($process.ExitCode -eq 0) {
        Write-Ok 'stopped on request and exited 0'
      }
      else {
        Write-Bad "exited $($process.ExitCode) after a requested stop"
      }
    }
    else {
      Write-Bad 'did not exit within 10s of a stop request'
      $process.Kill()
    }
  }
  finally {
    Get-Process sangfor-tunneld -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  }

  if ($TestAdapter) {
    Write-Step 'Driver install (throwaway adapter)'
    if (-not (Test-Admin)) {
      Write-Bad '-TestAdapter needs elevation'
    }
    else {
      $name = "sangfor-verify-$PID"
      $created = & $DaemonPath --device wintun --interface $name --check `
        --plan (Join-Path $scratch 'plan.json') 2>&1
      if ($LASTEXITCODE -eq 0) {
        Write-Ok "created and released the adapter '$name'"
      }
      else {
        Write-Bad "could not create an adapter: $created"
      }
    }
  }
}

function Wait-ForControlPort {
  param([string]$LogPath, [int]$TimeoutSeconds)
  $marker = 'control socket listening on 127.0.0.1:'
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $LogPath) {
      foreach ($line in Get-Content -LiteralPath $LogPath) {
        $index = $line.IndexOf($marker)
        if ($index -ge 0) {
          $port = 0
          if ([int]::TryParse($line.Substring($index + $marker.Length).Trim(), [ref]$port)) {
            return $port
          }
        }
      }
    }
    Start-Sleep -Milliseconds 100
  }
  return $null
}

function Send-ControlRequest {
  param([int]$Port, [hashtable]$Request)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $client.Connect([System.Net.IPAddress]::Loopback, $Port)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $writer.WriteLine(($Request | ConvertTo-Json -Compress))
    $reader = New-Object System.IO.StreamReader($stream)
    $line = $reader.ReadLine()
    if (-not $line) { return @{ ok = $false; error = 'the daemon closed the connection' } }
    return $line | ConvertFrom-Json
  }
  catch {
    return @{ ok = $false; error = $_.Exception.Message }
  }
  finally {
    $client.Close()
  }
}

# ---------------------------------------------------------------------------
# Stage 2: a real tunnel
# ---------------------------------------------------------------------------

function Invoke-RealTunnel {
  param([string]$DaemonPath)

  if (-not (Test-Admin)) {
    Write-Bad 'a real tunnel needs elevation to create the adapter and install routes'
    Write-Info 'Run this shell as administrator, or install the daemon as a service.'
    return
  }
  if (-not (Test-Path -LiteralPath $Plan)) {
    Write-Bad "no session plan at $Plan"
    Write-Info 'Export one from the app after logging in; see VERIFY.md.'
    return
  }
  if (-not $Config -and $Routes.Count -eq 0) {
    Write-Warn 'no routes given, so nothing will be routed through the tunnel'
    Write-Info 'Pass -Routes 10.0.0.0/8 (or whatever the gateway publishes), or a -Config that lists them.'
  }

  $scratch = Join-Path ([IO.Path]::GetTempPath()) "sangfor-verify-$PID"
  New-Item -ItemType Directory -Force -Path $scratch | Out-Null
  $logPath = Join-Path $scratch 'daemon.log'

  try {
    $configPath = $Config
    if (-not $configPath) {
      $configPath = Join-Path $scratch 'host.json'
      $token = [guid]::NewGuid().ToString('n')
      $config = [ordered]@{
        device       = 'wintun'
        interface    = 'Luotopia Verify'
        controlPort  = 0
        controlToken = $token
        routes       = $Routes
        dnsServers   = $Dns
      }
      if ($WintunDll) { $config.wintunDll = $WintunDll }
      $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -NoNewline
      $script:Token = $token
    }
    else {
      $parsed = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
      $script:Token = $parsed.controlToken
      if (-not $script:Token) {
        Write-Warn 'the configuration has no controlToken; any local process could stop this tunnel'
      }
    }

    Write-Step 'Starting the tunnel'
    $process = Start-Process -FilePath $DaemonPath `
      -ArgumentList '--plan', $Plan, '--config', $configPath `
      -RedirectStandardError $logPath -RedirectStandardOutput (Join-Path $scratch 'out.txt') `
      -PassThru -NoNewWindow

    $port = Wait-ForControlPort -LogPath $logPath -TimeoutSeconds 30
    if ($null -eq $port) {
      Write-Bad 'the daemon never reported a control port'
      Write-Info (Get-Content -LiteralPath $logPath -Raw)
      return
    }
    Write-Ok "control socket on 127.0.0.1:$port"

    Write-Step "Waiting up to $SettleSeconds s for the gateway"
    $deadline = (Get-Date).AddSeconds($SettleSeconds)
    $last = $null
    while ((Get-Date) -lt $deadline) {
      $reply = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $script:Token }
      if ($reply.ok) {
        $last = $reply.data
        if ($last.interfaceConfigured) { break }
        if ($last.fatal) { break }
      }
      Start-Sleep -Milliseconds 500
    }

    if ($null -eq $last) {
      Write-Bad 'the daemon never answered a status request'
      Write-Info (Get-Content -LiteralPath $logPath -Raw)
      return
    }

    Write-Step 'What the tunnel reports'
    Write-Info ($last | ConvertTo-Json -Compress)
    if ($last.fatal) {
      Write-Bad "the session died: $($last.fatal)"
      Write-Info 'This is a control-plane problem: the plan is stale, the credentials expired, or the gateway refused the handshake. Log in again and re-export.'
      return
    }
    if ($last.virtualIp.Count -gt 0) {
      Write-Ok "the gateway assigned $($last.virtualIp -join ', ')"
    }
    else {
      Write-Bad 'no virtual IP; the L3 handshake did not complete'
    }
    if ($last.interfaceConfigured) {
      Write-Ok 'the adapter was configured'
    }
    else {
      Write-Bad "the adapter was not configured: $($last.interfaceError)"
    }
    if ($last.connectFailures -gt 0) {
      Write-Warn "$($last.connectFailures) connect attempt(s) failed"
    }

    Write-Step 'Operating system view'
    $adapter = Get-NetAdapter -Name 'Luotopia Verify' -ErrorAction SilentlyContinue
    if ($adapter) {
      Write-Ok "adapter '$($adapter.Name)' is $($adapter.Status)"
      $addresses = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
      foreach ($address in $addresses) {
        Write-Info "address $($address.IPAddress)/$($address.PrefixLength)"
      }
    }
    else {
      Write-Warn "no adapter named 'Luotopia Verify'"
    }
    $tunnelRoutes = Get-NetRoute -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceAlias -eq 'Luotopia Verify' }
    if ($tunnelRoutes) {
      Write-Ok "$($tunnelRoutes.Count) route(s) through the adapter"
      foreach ($route in $tunnelRoutes | Select-Object -First 10) {
        Write-Info "$($route.DestinationPrefix) via $($route.NextHop)"
      }
    }
    else {
      Write-Warn 'no routes through the adapter'
    }

    # A route that captures a gateway node sends the tunnel's traffic into the
    # tunnel. The daemon excludes them and logs it; this confirms the exclusion
    # held from the operating system's side too.
    $planJson = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
    $nodes = @()
    foreach ($property in $planJson.nodes.PSObject.Properties) { $nodes += $property.Value }
    $conflicts = @()
    foreach ($node in $nodes) {
      $host_ = ($node -split ':')[0]
      $found = $tunnelRoutes | Where-Object {
        $prefix = $_.DestinationPrefix
        Test-RouteCovers -Address $host_ -Cidr $prefix
      }
      if ($found) { $conflicts += "$host_ is inside $($found.DestinationPrefix -join ', ')" }
    }
    if ($conflicts.Count -eq 0) {
      Write-Ok 'no gateway node is inside a tunnel route'
    }
    else {
      Write-Bad "the tunnel would capture its own gateway: $($conflicts -join '; ')"
    }

    if ($Probe) {
      Write-Step "Probing $Probe from outside the tunnel process"
      try {
        if ($Probe -match '^https?://') {
          $response = Invoke-WebRequest -Uri $Probe -TimeoutSec 20 -UseBasicParsing
          Write-Ok "HTTP $($response.StatusCode) from $Probe"
        }
        else {
          $parts = $Probe -split ':'
          $target = $parts[0]
          $targetPort = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }
          $client = New-Object System.Net.Sockets.TcpClient
          $async = $client.BeginConnect($target, $targetPort, $null, $null)
          if ($async.AsyncWaitHandle.WaitOne(20000)) {
            $client.EndConnect($async)
            Write-Ok "TCP connect to $target`:$targetPort succeeded"
          }
          else {
            Write-Bad "TCP connect to $target`:$targetPort timed out"
          }
          $client.Close()
        }
      }
      catch {
        Write-Bad "the probe failed: $($_.Exception.Message)"
      }
    }

    Write-Step 'Counters after the probe'
    $reply = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $script:Token }
    if ($reply.ok) {
      $after = $reply.data
      Write-Info "routed=$($after.routed) terminated=$($after.terminated) unrouted=$($after.unrouted) ingress=$($after.ingress) dropped=$($after.deviceDropped)"
      if ($after.routed -eq 0 -and $after.terminated -eq 0) {
        Write-Warn 'no egress packets reached the tunnel; is anything actually using it?'
      }
      if ($after.terminated -gt 0) {
        Write-Ok "$($after.terminated) packet(s) went through the userspace TCP terminator"
        Write-Info 'That is the path for resources the gateway publishes as TCP-tunnel-only.'
      }
      if ($after.unrouted -gt 0) {
        Write-Warn "$($after.unrouted) packet(s) matched no published resource"
      }
    }

    Write-Step 'Tearing down'
    Send-ControlRequest -Port $port -Request @{ cmd = 'stop'; token = $script:Token } | Out-Null
    if ($process.WaitForExit(15000)) {
      if ($process.ExitCode -eq 0) { Write-Ok 'exited 0' } else { Write-Bad "exited $($process.ExitCode)" }
    }
    else {
      Write-Bad 'did not exit within 15s of a stop request'
      $process.Kill()
    }

    Write-Step 'Daemon log'
    Get-Content -LiteralPath $logPath | ForEach-Object { Write-Info $_ }
  }
  finally {
    Get-Process sangfor-tunneld -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Test-RouteCovers {
  param([string]$Address, [string]$Cidr)
  if ($Address -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }
  if ($Cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { return $false }
  $prefix = [int]$Matches[2]
  $network = [uint32]0
  $octets = $Matches[1] -split '\.'
  foreach ($octet in $octets) { $network = ($network -shl 8) -bor [uint32]$octet }
  $target = [uint32]0
  foreach ($octet in ($Address -split '\.')) { $target = ($target -shl 8) -bor [uint32]$octet }
  if ($prefix -eq 0) { return $true }
  $mask = [uint32]::MaxValue -shl (32 - $prefix)
  return ($network -band $mask) -eq ($target -band $mask)
}

# ---------------------------------------------------------------------------

Write-Host 'sangfor-tunneld verification' -ForegroundColor White

$daemonPath = Find-Daemon
if (-not $daemonPath) {
  Write-Bad 'sangfor-tunneld was not found'
  Write-Info 'Build it with: cd rust; cargo build --release -p sangfor-tunneld'
  Write-Info 'Or pass -Daemon <path>.'
  exit 1
}
Write-Info "daemon: $daemonPath"

Invoke-Preflight -DaemonPath $daemonPath
if ($Plan) { Invoke-RealTunnel -DaemonPath $daemonPath }
elseif (-not $Preflight) {
  Write-Step 'Stage 2 skipped'
  Write-Info 'Pass -Plan <exported-plan.json> (and -Routes) to run a real tunnel.'
}

Write-Host ''
if ($script:Failures -gt 0) {
  Write-Host "$($script:Failures) check(s) failed, $($script:Warnings) warning(s)." -ForegroundColor Red
  exit 1
}
Write-Host "All checks passed ($($script:Warnings) warning(s))." -ForegroundColor Green
exit 0
