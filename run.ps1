# run.ps1 — TrustField one-shot setup and launch script (Windows)
#
# Usage:
#   .\run.ps1                    # setup (if needed) + start dashboard
#   .\run.ps1 -Test              # setup + run test suite, then start dashboard
#   .\run.ps1 -Demo              # setup + run full pipeline demo, then start dashboard
#   .\run.ps1 -TestOnly          # setup + run tests, exit (no server)
#   .\run.ps1 -DemoOnly          # setup + run pipeline demo, exit (no server)
#   .\run.ps1 -Port 8080         # start dashboard on a custom port
#   .\run.ps1 -STM32 COM6        # enable STM32 hardware guard on COM6

param(
    [switch]$Test,
    [switch]$Demo,
    [switch]$TestOnly,
    [switch]$DemoOnly,
    [int]$Port = 5000,
    [string]$STM32 = "",
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# ── Helpers ───────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host ">" $msg -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[OK]" $msg -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[!]" $msg -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[X]" $msg -ForegroundColor Red; exit 1 }
function Write-Divider { Write-Host ("=" * 50) -ForegroundColor DarkGray }

# ── Help ──────────────────────────────────────────────────────────────────
if ($Help) {
    Get-Content $MyInvocation.MyCommand.Definition | Select-Object -Skip 1 -First 8 | ForEach-Object { $_ -replace '^# ?', '' }
    exit 0
}

# ── Banner ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  TRUSTFIELD" -ForegroundColor Cyan
Write-Host "  Trust Propagation & Containment System" -ForegroundColor DarkGray
Write-Host "  RV College of Engineering - Team PS-11" -ForegroundColor DarkGray
Write-Host ""
Write-Divider

# ── Step 1: Python version check ─────────────────────────────────────────
Write-Info "Checking Python version..."

$pythonCmd = $null
foreach ($candidate in @("python", "python3")) {
    try {
        $ver = & $candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver) { $pythonCmd = $candidate; break }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Fail "Python not found. Install Python 3.10 or higher."
}

$pyMajor = & $pythonCmd -c "import sys; print(sys.version_info.major)"
$pyMinor = & $pythonCmd -c "import sys; print(sys.version_info.minor)"
$pyVer   = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"

if ([int]$pyMajor -lt 3 -or ([int]$pyMajor -eq 3 -and [int]$pyMinor -lt 10)) {
    Write-Fail "Python 3.10+ required. Found: $pyVer"
}

Write-Success "Python $pyVer"

# ── Step 2: Virtual environment ───────────────────────────────────────────
$VenvDir = Join-Path $ScriptDir ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip    = Join-Path $VenvDir "Scripts\pip.exe"
$VenvActivate = Join-Path $VenvDir "Scripts\Activate.ps1"

if (-not (Test-Path $VenvDir)) {
    Write-Info "Creating virtual environment at .venv ..."
    & $pythonCmd -m venv $VenvDir
    Write-Success "Virtual environment created"
} else {
    Write-Success "Virtual environment already exists"
}

# Activate
& $VenvActivate
Write-Success "Virtual environment activated"

# ── Step 3: Install / sync dependencies ───────────────────────────────────
Write-Info "Installing dependencies from requirements.txt ..."

$reqFile = Join-Path $ScriptDir "requirements.txt"
& $VenvPip install --quiet --upgrade pip 2>$null
& $VenvPip install --quiet -r $reqFile 2>$null

Write-Success "Dependencies installed"
Write-Divider

# ── Step 4: Optional — run tests ─────────────────────────────────────────
$RunTests  = $Test -or $TestOnly
$RunDemo   = $Demo -or $DemoOnly
$StartServer = -not $TestOnly -and -not $DemoOnly

if ($RunTests) {
    Write-Info "Running test suite..."
    Write-Host ""

    Set-Location $ScriptDir
    $env:PYTHONPATH = "."
    & $VenvPython -m pytest tests/ -q --tb=short

    if ($LASTEXITCODE -eq 0) {
        Write-Success "All tests passed"
    } else {
        Write-Warn "Some tests failed (check output above)"
    }

    Write-Host ""
    Write-Divider
}

# ── Step 5: Optional — run full pipeline demo ────────────────────────────
if ($RunDemo) {
    Write-Info "Running full pipeline demo (all 4 topologies)..."
    Write-Host ""

    Set-Location $ScriptDir
    $env:PYTHONPATH = "."
    & $VenvPython (Join-Path "demos" "demo_full_pipeline.py")

    Write-Success "Demo complete - outputs written to out/"
    Write-Host ""
    Write-Divider
}

# ── Step 6: Start dashboard server ────────────────────────────────────────
if ($StartServer) {
    Write-Info "Starting TrustField dashboard on port $Port ..."
    Write-Host ""
    Write-Host "  Open:  " -NoNewline; Write-Host "http://127.0.0.1:$Port" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Tabs:   HUB / CHAIN / DENSE / MIXED - synthetic topologies" -ForegroundColor DarkGray
    Write-Host "          SIM - live simulated infrastructure" -ForegroundColor DarkGray
    Write-Host "          ORG - real AWS IAM data upload" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  SIM tab controls:" -ForegroundColor DarkGray
    Write-Host "    INFRA  -> open infrastructure editor" -ForegroundColor DarkGray
    Write-Host "    RUN    -> run full 6-module pipeline analysis" -ForegroundColor DarkGray
    Write-Host "    Click node -> SIMULATE BREACH -> run from that entry point" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Press Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Divider
    Write-Host ""

    Set-Location $ScriptDir
    $env:PYTHONPATH = "."

    $serverArgs = @("server.py", "--port", $Port)
    if ($STM32) {
        $serverArgs += @("--stm32", $STM32)
    }
    & $VenvPython @serverArgs
}
