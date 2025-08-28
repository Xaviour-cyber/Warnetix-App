param(
  [string]$OpenSSLRoot = "C:\OpenSSL-Win64" # opsional
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root

$build = Join-Path $proj "build"
if (-not (Test-Path $build)) { New-Item -ItemType Directory -Path $build | Out-Null }

$cmakeArgs = @("-S", "agent", "-B", "build", "-A", "x64")
if (Test-Path $OpenSSLRoot) {
  $cmakeArgs += "-DOPENSSL_ROOT_DIR=$OpenSSLRoot"
}

cmake @cmakeArgs
cmake --build build --config Release
Write-Host "Done. EXE: build\Release\warnetix_agent.exe"
// agent_config.cpp - Configuration loading for the agent