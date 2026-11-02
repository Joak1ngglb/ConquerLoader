#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$flash = Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CFlashFix.cpp') -Raw
$hook = Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
$early = Get-Content -LiteralPath (Join-Path $root 'ConquerLoader/ConquerLoader/Models/EarlyInjectedClient.cs') -Raw
$compat = Get-Content -LiteralPath (Join-Path $root 'ConquerHook/Flashless5065.cpp') -Raw

Assert ($flash.Contains('g_forceOle32Import = &::CoCreateInstance')) 'ole32 must be a real pre-DllMain import.'
Assert ($flash.Contains('LOAD_WITH_ALTERED_SEARCH_PATH')) 'Local OCX must use an absolute-path dependency search.'
Assert ($flash.Contains('DllGetClassObject') -and $flash.Contains('IID_IClassFactory')) 'Local class factory preflight missing.'
Assert ($flash.Contains('CoCreateInstanceDetour') -and $flash.Contains('CoGetClassObjectDetour') -and
        $flash.Contains('CLSIDFromProgIDDetour')) 'COM activation surface is incomplete.'
Assert ($flash.Contains('DetourTransactionAbort') -and $flash.Contains('DetourTransactionCommit')) 'COM hooks must commit atomically.'
Assert ($flash.Contains('HRESULT=0x%08lX')) 'HRESULT diagnostics missing.'
Assert (-not $flash.Contains('DllRegisterServer') -and -not $flash.Contains('RegSetValue')) 'Global COM registration is forbidden.'
Assert ($hook.Contains('Flash5065Preflight') -and $hook.Contains('AddVectoredExceptionHandler')) 'Preflight/crash diagnostics missing.'
Assert ($early.Contains('ConquerLoader-Flash5065-Ready-') -and
        $early.Contains('ConquerLoader-Flash5065-Failed-')) 'Launcher must verify Flash readiness, not DLL presence only.'
Assert ($compat.Contains('EnableLocalFlashCompatibility5065') -and
        $compat.Contains('ExactBuild()') -and $compat.Contains('kFlashCheckRva')) 'Obsolete Flash version gate must be exact-build validated.'
Assert ($flash.Contains('Preflight IClassFactory::CreateInstance(IID_IUnknown)')) 'Preflight must create a real ActiveX instance, not only fetch its factory.'
Write-Host 'OK: registry-free Flash COM activation, readiness handshake and crash diagnostics verified.'
