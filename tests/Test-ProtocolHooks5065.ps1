#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$hook=Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
$early=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
function Assert([bool]$ok,[string]$reason){if(-not $ok){throw $reason}}
Assert ($hook.Contains('MainImportDirectory') -and $hook.Contains('IMAGE_DIRECTORY_ENTRY_IMPORT')) 'Protocol resolver must inspect the real Conquer.exe PE imports.'
Assert ($hook.Contains('ResolveMainImport("_snprintf")') -and $hook.Contains('ResolveMainImport("snprintf")')) 'CRT snprintf variants are not detected.'
Assert (-not $hook.Contains('GetModuleHandleA("msvcr90.dll")')) 'Protocol hooks must not assume msvcr90.dll.'
Assert ($hook.Contains('Protocol resolve function=%s module=%s address=0x%p')) 'Per-function/module resolution logging missing.'
Assert ($hook.Contains('Detour statuses transaction=') -and $hook.Contains('connect=%ld send=%ld snprintf=%ld')) 'Per-hook Detours logging missing.'
Assert ($hook.Contains('if (allAttached && committed == NO_ERROR)')) 'An aborted Detours transaction must never publish protocol readiness.'
Assert ($hook.Contains('connect route=%s redirected=%s original=%s:%d target=%s:%d')) 'Connection redirection logging missing.'
Assert ($hook.Contains('getpeername') -and $hook.Contains('verified=%s')) 'Actual peer verification missing.'
Assert ($hook.Contains('Authentication packet legacy decrypt/patch/encrypt complete')) 'Authentication cipher diagnostics missing.'
Assert ($hook.Contains('legacy && s == g_loginSocket')) 'Authentication cipher must only touch the identified login socket.'
Assert ($hook.Contains('value redacted')) 'Password diagnostics must explicitly redact values.'
Assert ($hook.Contains('ConquerLoader-Protocol5065-%s-%lu') -and
        $early.Contains('ConquerLoader-Protocol5065-Ready-') -and
        $early.Contains('ConquerLoader-Protocol5065-Failed-')) 'Launcher must wait for protocol hook readiness/failure.'
Assert ($early.Contains('Destino Redux y autenticacion se verificaran al conectar/enviar')) 'Launcher must not claim connection success from hook readiness.'
Write-Host 'OK: dynamic CRT/Winsock import resolution and Redux destination/auth verification wired.'
