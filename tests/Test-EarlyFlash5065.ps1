# Validate the key startup invariant without injecting any DLL into CI.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$early=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
$launcher=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Forms/WPF/MainLite.xaml.cs') -Raw
$proj=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/ConquerLoader.csproj') -Raw
function Assert($ok,$reason) { if(-not $ok){throw $reason} }
Assert ($early.Contains('CreateSuspended') -and $early.Contains('QueueUserAPC(') -and $early.Contains('ResumeThread(')) 'Missing suspend/APC/resume sequence'
Assert ($early.IndexOf('QueueUserAPC(loadLibrary') -lt $early.IndexOf('ResumeThread(info.hThread)')) 'DLL must be queued BEFORE resuming the game'
Assert ($launcher.Contains('SelectedServer.ServerVersion == 5065 && !CustomDLLs')) 'Every 5065 login mode must use the early hook'
Assert ($launcher.Contains('Skipping late duplicate CLHook injection.')) 'Second DLL injection not disabled'
$hook=Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
Assert ($launcher.Contains('EARLY_FLASH5065=')) 'Early startup flag missing'
Assert ($hook.Contains('Deferred5065ProtocolHooks') -and $hook.Contains('EARLY_FLASH5065')) 'Pre-entry networking must be deferred'
Assert ($hook.Contains('ResolveMainImport("connect")') -and
        $hook.Contains('ResolveMainImport("send")') -and
        $hook.Contains('ResolveMainImport("_snprintf")')) 'All Redux protocol imports must be resolved from Conquer.exe'
Assert ($launcher.Contains('Conquer.exe finalizo. PID=')) 'Client exit code must be logged'
Assert ($launcher.Contains('FLASH5065_DIAGNOSTIC_MODE=')) 'Diagnostic mode flag missing from CLHook.ini'
Assert ($hook.Contains('Flash detour installation returned HRESULT=')) 'Flash hook HRESULT stage not logged'
Assert ($hook.Contains('Network hook skipped in diagnostic mode.')) 'Missing Flash-only isolation mode'
$profile = Get-Content -LiteralPath (Join-Path $root 'profiles/redux-5065.local.json') -Raw | ConvertFrom-Json
Assert ($profile.UseOriginalFlashLogin -eq $true) 'Original Flash login must be the default'
Assert ($profile.Flash5065DiagnosticMode -eq 0) 'Flash profile must enable normal networking'
Assert ($proj.Contains('Models\EarlyInjectedClient.cs')) 'Early injector missing from C# compilation'
Write-Host 'OK: Dragon-style pre-entry Flash hook wired and scoped to 5065.'
