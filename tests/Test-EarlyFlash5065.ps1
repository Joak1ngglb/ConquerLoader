# Validate the key startup invariant without injecting any DLL into CI.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$early=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
$launcher=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Forms/WPF/MainLite.xaml.cs') -Raw
$proj=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/ConquerLoader.csproj') -Raw
function Assert($ok,$reason) { if(-not $ok){throw $reason} }
Assert ($early.Contains('CreateSuspended') -and $early.Contains('QueueUserAPC(') -and $early.Contains('ResumeThread(')) 'Missing suspend/APC/resume sequence'
Assert ($early.IndexOf('QueueUserAPC(loadLibrary') -lt $early.IndexOf('ResumeThread(info.hThread)')) 'DLL must be queued BEFORE resuming the game'
Assert ($launcher.Contains('LoaderConfig.UseOriginalFlashLogin && !CustomDLLs')) 'Only original Flash 5065 uses early hook'
Assert ($launcher.Contains('Skipping late duplicate CLHook injection.')) 'Second DLL injection not disabled'
$hook=Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
Assert ($launcher.Contains('EARLY_FLASH5065=')) 'Early startup flag missing'
Assert ($hook.Contains('Deferred5065ConnectHook') -and $hook.Contains('EARLY_FLASH5065')) 'Pre-entry networking must be deferred'
Assert ($hook.Contains('if (connectAddress)')) 'Do not hook a NULL winsock function'
Assert ($launcher.Contains('Conquer.exe finalizo. PID=')) 'Client exit code must be logged'
Assert ($launcher.Contains('FLASH5065_DIAGNOSTIC_MODE=')) 'Diagnostic mode flag missing from CLHook.ini'
Assert ($hook.Contains('Flash detour installation returned.')) 'Flash hook stages not logged'
Assert ($hook.Contains('Network hook skipped in diagnostic mode.')) 'Missing Flash-only isolation mode'
$profile = Get-Content -LiteralPath (Join-Path $root 'profiles/redux-5065.local.json') -Raw | ConvertFrom-Json
Assert ($profile.Flash5065DiagnosticMode -eq 1) 'New user profile should isolate the network hook by default'
Assert ($proj.Contains('Models\EarlyInjectedClient.cs')) 'Early injector missing from C# compilation'
Write-Host 'OK: Dragon-style pre-entry Flash hook wired and scoped to 5065.'
