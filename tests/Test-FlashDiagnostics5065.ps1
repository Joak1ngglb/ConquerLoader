#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$script=Get-Content -LiteralPath (Join-Path $root 'tools/Diagnose-Crash5065.ps1') -Raw
function Assert([bool]$ok,[string]$reason){if(-not $ok){throw $reason}}
Assert ($script.Contains('Last Flash stage:')) 'Crash report must identify the last Flash activation stage.'
Assert ($script.Contains('Last HRESULT:')) 'Crash report must surface the last COM HRESULT.'
Assert ($script.Contains('Last exception:')) 'Crash report must surface AV address/module/register diagnostics.'
Assert ($script.Contains("'Conquer.exe','Flash.ocx','CLHook.dll'")) 'Crash report must fingerprint all runtime binaries.'
Assert ($script.Contains('Get-FileHash') -and $script.Contains('SHA256=')) 'SHA-256 identity is required.'
Write-Host 'OK: Flash crash report summarizes stage, HRESULT, exception and binary identity.'
