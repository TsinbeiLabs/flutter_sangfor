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

.PARAMETER Installed
  Also drive a daemon that was installed with `--install`, from *this* shell.
  The point is that this shell is not elevated: a session started here is one
  the app could have started, which is the whole reason the logon task exists.
  Needs `-Plan` to start a session; without it, only reachability is checked.

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
  [switch]$Installed,
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
    # Parenthesised: `Write-Warn 'a' + 'b'` parses as the command `Write-Warn 'a'`
    # followed by a separate expression, so the continuation is emitted to the
    # output stream on its own and appears at the end of the run, nowhere near
    # the warning it belongs to.
    Write-Warn ('not elevated. Preflight still runs, but a real tunnel needs ' +
      'elevation -- which is exactly what installing the daemon as a logon ' +
      'task removes from the app.')
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

  Write-Step 'Install command (what removing the elevation prompt needs)'
  # Printed, not run: creating the logon task needs an elevated shell, and this
  # stage is the one that works without any privilege. Showing the command is
  # the useful half anyway -- whoever runs it should see it first.
  if (-not $IsWindows -and $PSVersionTable.Platform -ne 'Win32NT') {
    Write-Warn 'the logon task is a Windows mechanism; install a systemd unit here'
  }
  else {
    $install = & $DaemonPath --print-install 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Bad "--print-install exited $LASTEXITCODE"
      Write-Info ($install -join "`n")
    }
    elseif (-not ($install -join "`n").Contains('/RL HIGHEST')) {
      # Without this flag the task runs exactly as unelevated as the app does,
      # and opening the adapter fails the same way it does today.
      Write-Bad 'the install command does not ask for elevation'
      Write-Info ($install -join "`n")
    }
    else {
      Write-Ok 'the install command asks for an elevated logon task'
      foreach ($line in $install) { Write-Info $line }
      if (Test-Admin) {
        Write-Info 'This shell is elevated: run the /Create line above to install it.'
      }
      else {
        Write-Info 'Run the /Create line above from an elevated shell to install it.'
      }
    }
  }

  Write-Step 'Dry run (in-memory device, no privileges needed)'
  $scratch = Join-Path ([IO.Path]::GetTempPath()) "sangfor-verify-$PID"
  New-Item -ItemType Directory -Force -Path $scratch | Out-Null
  try {
    $planPath = Write-VerifyPlan -Directory $scratch
    $configPath = Join-Path $scratch 'host.json'
    $token = "preflight-$PID"
    @{
      device       = 'loopback'
      interface    = 'sangfor-preflight'
      controlPort  = 0
      controlToken = $token
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $configPath -NoNewline

    $stderrPath = Join-Path $scratch 'daemon.log'
    # Launched with no plan, which is the shape an installed daemon has: it
    # starts at logon with nothing to do and is handed a session later. Driving
    # it that way here is what proves the install path works, because a daemon
    # given `--plan` never exercises `start` at all.
    $process = Start-Process -FilePath $DaemonPath `
      -ArgumentList '--dry-run', '--config', $configPath `
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

    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
    if ($status.ok) {
      Write-Ok 'status answered'
      Write-Info ($status.data | ConvertTo-Json -Compress)
      if ($status.data.sessionRunning) {
        Write-Bad 'a daemon with no plan reports a running session'
      }
      else {
        Write-Ok 'it starts idle, with no session'
      }
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

    # `start` is the verb that hands a daemon its session, and the one that most
    # needs gating: it points the process at a plan, and therefore at a gateway,
    # with a signing key.
    $unauthorized = Send-ControlRequest -Port $port -Request @{ cmd = 'start'; planPath = $planPath }
    if (-not $unauthorized.ok) {
      Write-Ok 'start without the token was refused, as it should be'
    }
    else {
      Write-Bad 'start succeeded without a token; any local process could take the tunnel over'
    }

    $started = Send-ControlRequest -Port $port -Request @{ cmd = 'start'; planPath = $planPath; token = $token }
    if ($started.ok) {
      Write-Ok 'start ran a session from a plan it was pointed at'
    }
    else {
      Write-Bad "start was refused: $($started | ConvertTo-Json -Compress)"
      Write-Info (Get-Content -LiteralPath $stderrPath -Raw)
      return
    }
    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
    if ($status.ok -and $status.data.sessionRunning) {
      Write-Ok "the session is running on $($status.data.interface)"
    }
    else {
      Write-Bad "the session is not running: $($status | ConvertTo-Json -Compress)"
    }

    $stopped = Send-ControlRequest -Port $port -Request @{ cmd = 'stopSession'; token = $token }
    if ($stopped.ok -and -not $process.HasExited) {
      Write-Ok 'stopSession ended the session and left the process up'
    }
    elseif ($process.HasExited) {
      Write-Bad "stopSession ended the whole process (exit $($process.ExitCode))"
    }
    else {
      Write-Bad "stopSession was refused: $($stopped | ConvertTo-Json -Compress)"
    }
    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
    if ($status.ok -and -not $status.data.sessionRunning) {
      Write-Ok 'it is idle again'
    }
    else {
      Write-Bad "it still reports a session: $($status | ConvertTo-Json -Compress)"
    }

    # The check that matters most for an installed daemon: one elevated process
    # has to serve every connect/disconnect cycle, not just the first. A second
    # session breaks quietly if the device, the snapshot, or the configurator
    # thread stayed bound to the one before it.
    $again = Send-ControlRequest -Port $port -Request @{ cmd = 'start'; planPath = $planPath; token = $token }
    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
    if ($again.ok -and $status.ok -and $status.data.sessionRunning) {
      Write-Ok 'a second session started on the same process'
      if ($status.data.connectFailures -ne 0) {
        Write-Warn "the second session inherited counters from the first (connectFailures=$($status.data.connectFailures))"
      }
    }
    else {
      Write-Bad "the second session did not start: $($again | ConvertTo-Json -Compress)"
      Write-Info (Get-Content -LiteralPath $stderrPath -Raw)
    }

    Send-ControlRequest -Port $port -Request @{ cmd = 'stop'; token = $token } | Out-Null
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
      # Its own scratch directory: the preflight one was removed above, and
      # pointing `--plan` at a file that is gone reports a driver failure that
      # is really a missing document.
      $adapterScratch = Join-Path ([IO.Path]::GetTempPath()) "sangfor-adapter-$PID"
      New-Item -ItemType Directory -Force -Path $adapterScratch | Out-Null
      try {
        $name = "sangfor-verify-$PID"
        $created = & $DaemonPath --device wintun --interface $name --check `
          --plan (Write-VerifyPlan -Directory $adapterScratch) 2>&1
        if ($LASTEXITCODE -eq 0) {
          Write-Ok "created and released the adapter '$name'"
        }
        else {
          Write-Bad "could not create an adapter: $created"
        }
      }
      finally {
        Remove-Item -LiteralPath $adapterScratch -Recurse -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

function Write-VerifyPlan {
  <#
    Writes a syntactically valid session plan and returns its path.

    It names a documentation-range node, so a tunnel built from it comes up and
    then fails to connect. That is the point: these stages check the process,
    not the gateway, and a node that cannot be reached is one that cannot be
    reached by anybody.
  #>
  param([string]$Directory)
  $path = Join-Path $Directory 'plan.json'
  @'
{"schemaVersion":1,"sid":"preflight","deviceId":"dev","connectionId":"conn",
 "username":"user","signKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
 "lang":"en","processName":"tunneld","processPath":"C:\\tunneld.exe",
 "processPlatform":"windows","nodes":{"major":["203.0.113.9:441"]},
 "majorNodeGroup":"major","routes":[],"dnsServers":[],"heartbeatSeconds":2}
'@ | Set-Content -LiteralPath $path -NoNewline
  return $path
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
    Write-Info 'Run this shell as administrator, or install the daemon with --install and drive it from an ordinary shell.'
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

# ---------------------------------------------------------------------------
# Stage 3: a daemon that was installed, driven from an ordinary shell
# ---------------------------------------------------------------------------

function Invoke-InstalledDaemon {
  <#
    The check that proves the elevation prompt is actually gone.

    Stages 1 and 2 run the daemon in the foreground of this shell, so they
    inherit whatever privilege it has. An installed daemon does not: it was
    started by the logon task, elevated, and this function talks to it over the
    loopback socket from here. If this shell is not elevated and a session
    starts, then an unelevated app can drive a tunnel -- which is the entire
    point of installing it.
  #>
  Write-Step 'Installed daemon (driven from this shell)'

  if (Test-Admin) {
    Write-Warn 'this shell is elevated, so a success here does not prove the app could do it'
    Write-Info 'Re-run from an ordinary shell for the check that matters.'
  }
  else {
    Write-Ok 'this shell is not elevated, which is what the app runs as'
  }

  $directory = Join-Path $env:LOCALAPPDATA 'sangfor-tunneld'
  $configPath = Join-Path $directory 'host.json'
  if (-not (Test-Path -LiteralPath $configPath)) {
    Write-Bad "no configuration at $configPath"
    Write-Info "Install it from an elevated shell: sangfor-tunneld --install"
    Write-Info 'Then log off and on again, or run the task once with schtasks /Run /TN SangforTunnel.'
    return
  }

  $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
  $port = if ($config.controlPort) { [int]$config.controlPort } else { 7166 }
  $token = $config.controlToken
  if (-not $token) {
    Write-Warn 'the installed configuration has no control token; any local process can drive it'
  }
  Write-Info "configuration: $configPath"
  Write-Info "control port:  $port"

  $ping = Send-ControlRequest -Port $port -Request @{ cmd = 'ping' }
  if (-not $ping.ok) {
    Write-Bad "nothing is answering on 127.0.0.1:$port"
    Write-Info 'The task may not have run yet: schtasks /Run /TN SangforTunnel'
    Write-Info "Its own log is at $(Join-Path $directory 'tunneld.log')"
    return
  }
  Write-Ok 'the installed daemon is answering, from an ordinary shell'

  $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
  if (-not $status.ok) {
    Write-Bad "status was refused: $($status | ConvertTo-Json -Compress)"
    Write-Info 'The token in the configuration does not match the running daemon.'
    return
  }
  Write-Ok 'status answered'
  Write-Info ($status.data | ConvertTo-Json -Compress)
  if ($status.data.sessionRunning) {
    Write-Warn 'a session is already running; this stage will not replace it'
    Write-Info 'Send {"cmd":"stopSession"} first, or disconnect from the app.'
    return
  }

  if (-not $Plan) {
    Write-Ok 'reachable and idle, which is what an app expects to find'
    Write-Info 'Pass -Plan <plan.json> to start a real session through it.'
    return
  }

  $started = Send-ControlRequest -Port $port -Request @{
    cmd = 'start'; planPath = (Resolve-Path $Plan).Path; token = $token
  }
  if (-not $started.ok) {
    Write-Bad "start was refused: $($started | ConvertTo-Json -Compress)"
    Write-Info "The daemon's own log will say why: $(Join-Path $directory 'tunneld.log')"
    return
  }
  Write-Ok 'an unelevated shell started a session in an elevated daemon'

  $deadline = (Get-Date).AddSeconds($SettleSeconds)
  $up = $null
  while ((Get-Date) -lt $deadline) {
    $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
    if ($status.ok -and ($status.data.interfaceConfigured -or $status.data.fatal)) { break }
    Start-Sleep -Milliseconds 500
  }
  if ($status.data.fatal) {
    Write-Bad "the session died: $($status.data.fatal)"
  }
  elseif ($status.data.interfaceConfigured) {
    Write-Ok "the interface came up as $($status.data.interface) with $($status.data.virtualIp -join ', ')"
  }
  else {
    Write-Warn "the interface was not configured within $SettleSeconds s"
  }
  Write-Info ($status.data | ConvertTo-Json -Compress)

  Write-Step 'Installed daemon log'
  $logPath = Join-Path $directory 'tunneld.log'
  if (Test-Path -LiteralPath $logPath) {
    Get-Content -LiteralPath $logPath -Tail 40 | ForEach-Object { Write-Info $_ }
  }
  else {
    Write-Warn "no log at $logPath"
  }

  # stopSession, not stop: the daemon is installed and the next connect wants
  # it. Ending the process here would leave the app with nothing to talk to
  # until the next logon.
  Send-ControlRequest -Port $port -Request @{ cmd = 'stopSession'; token = $token } | Out-Null
  $status = Send-ControlRequest -Port $port -Request @{ cmd = 'status'; token = $token }
  if ($status.ok -and -not $status.data.sessionRunning) {
    Write-Ok 'the session ended and the daemon stayed up for the next one'
  }
  else {
    Write-Bad "the daemon did not return to idle: $($status | ConvertTo-Json -Compress)"
  }
}

function Test-RouteCovers {
  param([string]$Address, [string]$Cidr)
  if ($Address -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }  if ($Cidr -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { return $false }
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
  Write-Info 'Or download a published one from the tunneld-v* releases of TsinbeiLabs/flutter_sangfor.'
  Write-Info 'A Flutter Windows build stages one beside the runner: build\windows\x64\runner\<Config>\sangfor-tunneld.exe'
  Write-Info 'Or pass -Daemon <path>.'
  exit 1
}
Write-Info "daemon: $daemonPath"

Invoke-Preflight -DaemonPath $daemonPath
if ($Plan) { Invoke-RealTunnel -DaemonPath $daemonPath }
if ($Installed) { Invoke-InstalledDaemon }
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
