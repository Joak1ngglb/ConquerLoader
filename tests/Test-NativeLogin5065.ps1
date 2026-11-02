#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
$native = Get-Content -LiteralPath (Join-Path $root 'ConquerHook/Flashless5065.cpp') -Raw
$hook = Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
$injector = Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
$profile = Get-Content -LiteralPath (Join-Path $root 'profiles/redux-5065.local.json') -Raw | ConvertFrom-Json

Assert ($native.Contains('kExpectedSha256') -and
        $native.Contains('0x97,0xcc,0xc3,0x27')) 'Native DLL must verify the supported client SHA-256.'
Assert ($injector.Contains('97CCC3276D46D46BB91AD62E758D1FB622C036F6224EED5EA7C121A80E550A89')) 'Launcher hash gate missing.'
Assert ($native.Contains('kNativeLoginRva') -and -not $native.Contains('kNativeLogin=0x')) 'Login target must be an RVA behind exact-build validation.'
Assert ($native.IndexOf('ExactBuild()') -lt $native.IndexOf('WriteCode(g_image+kFlashCheckRva')) 'Validation must precede patching.'
Assert ($hook.Contains('Deferred5065NativeProtocolHooks')) 'Native Redux protocol hooks must be deferred.'
Assert ($hook.Contains('DetourAttach(reinterpret_cast<PVOID*>(&native5065_connect)') -and
        $hook.Contains('DetourAttach(reinterpret_cast<PVOID*>(&native5065_send)')) 'Native networking must use Detours trampolines.'
Assert ($hook.Contains('if (flashless)') -and $hook.Contains('return;')) 'Native mode must not fall through to generic legacy patching.'
Assert ($profile.UseOriginalFlashLogin -eq $false) 'Native login must be the distributed default.'
Write-Host 'OK: exact-build native 5065 login, early injection and deferred protocol hooks verified.'
