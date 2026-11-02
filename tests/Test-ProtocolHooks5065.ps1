#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$hook=Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
$early=Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
function Assert([bool]$ok,[string]$reason){if(-not $ok){throw $reason}}
Assert ($hook.Contains('MainImportDirectory') -and $hook.Contains('IMAGE_DIRECTORY_ENTRY_IMPORT')) 'Protocol resolver must inspect the real Conquer.exe PE imports.'
Assert (-not $hook.Contains('ResolveMainImport("_snprintf")') -and -not $hook.Contains('protocol5065_snprintf')) '5065 must not detour process-wide CRT varargs functions.'
Assert ($hook.Contains('if(ClientVersion==5065) {') -and $hook.Contains('5065 fallback: installing Winsock-only protocol hooks')) 'Every 5065 configuration must bypass the legacy CRT hook path.'
Assert (-not $hook.Contains('GetModuleHandleA("msvcr90.dll")')) 'Protocol hooks must not assume msvcr90.dll.'
Assert ($hook.Contains('Protocol resolve function=%s module=%s address=0x%p')) 'Per-function/module resolution logging missing.'
Assert ($hook.Contains('Detour statuses transaction=') -and $hook.Contains('connect=%ld send=%ld; CRT detour=disabled')) 'Per-hook Detours logging missing.'
Assert ($hook.Contains('if (allAttached && committed == NO_ERROR)')) 'An aborted Detours transaction must never publish protocol readiness.'
Assert ($hook.Contains('connect route=%s redirected=%s original=%s:%d target=%s:%d')) 'Connection redirection logging missing.'
Assert ($hook.Contains('getpeername') -and $hook.Contains('verified=%s')) 'Actual peer verification missing.'
Assert ($hook.Contains('payload is read-only') -and $hook.Contains('forwarded byte-for-byte')) '5065 authentication traffic must be pass-through.'
$send5065=$hook.Substring($hook.IndexOf('if(ClientVersion==5065)'))
$send5065=$send5065.Substring(0,$send5065.IndexOf('else if (legacy'))
Assert (-not $send5065.Contains('Decrypt(') -and -not $send5065.Contains('Encrypt(') -and
        -not $send5065.Contains('memcpy') -and -not $send5065.Contains('szPassword')) '5065 send observer must not inspect or mutate credentials.'
Assert ($hook.Contains('__declspec(thread) LONG g_sendHookDepth') -and $hook.Contains('stack-marker-stable=')) 'Recursion/stack diagnostics missing.'
Assert ($hook.Contains('LogExceptionStack5065') -and $hook.Contains('ebp-return') -and $hook.Contains('esp-code')) 'Crash call trace missing.'
Assert ($hook.Contains('ConquerLoader-Protocol5065-%s-%lu') -and
        $early.Contains('ConquerLoader-Protocol5065-Ready-') -and
        $early.Contains('ConquerLoader-Protocol5065-Failed-')) 'Launcher must wait for protocol hook readiness/failure.'
Assert ($early.Contains('Destino Redux y autenticacion se verificaran al conectar/enviar')) 'Launcher must not claim connection success from hook readiness.'
Write-Host 'OK: Winsock-only hooks, read-only 5065 packets and x86 crash tracing wired.'
