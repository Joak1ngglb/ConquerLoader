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
Assert ($proj.Contains('Models\EarlyInjectedClient.cs')) 'Early injector missing from C# compilation'
Write-Host 'OK: Dragon-style pre-entry Flash hook wired and scoped to 5065.'
