# Configures, builds and tests one preset: scripts\build.ps1 [windows-x64 | windows-x86]

param([string]$Preset = "windows-x64")

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

cmake --preset $Preset
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build --preset $Preset --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

ctest --preset $Preset
exit $LASTEXITCODE
