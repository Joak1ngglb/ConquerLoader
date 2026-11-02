#Requires -Version 5.1
<#
.SYNOPSIS
  Diagnostico de inicio Flash/ActiveX del cliente Conquer Online 5065.
.DESCRIPTION
  Solo lectura: NO carga Flash.ocx, NO registra OCX/DLL, NO inicia Conquer.exe,
  NO modifica el registro, antivirus ni archivos del cliente.
.EXAMPLE
  .\Diagnose-Flash5065.ps1 -ClientDirectory 'C:\Juegos\Conquer Online'
#>
[CmdletBinding()]
param([string]$ClientDirectory = $PSScriptRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Info([string]$Label, [object]$Value) {
    Write-Host ("{0}: {1}" -f $Label, $Value)
}
function Read-ImageMachine([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'ARCHIVO AUSENTE' }
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = New-Object System.IO.BinaryReader($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { return 'No es PE valido (MZ)' }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 0 -or $offset -gt ($stream.Length - 6)) { return 'PE invalido (offset)' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { return 'PE invalido (cabecera)' }
        switch ($reader.ReadUInt16()) {
            0x014c { return 'x86 (32 bits)' }
            0x8664 { return 'x64 (64 bits)' }
            default { return 'Arquitectura no reconocida' }
        }
    } finally {
        $reader.Dispose()
    }
}
function Query-FlashRegistration {
    $clsid = '{D27CDB6E-AE6D-11CF-96B8-444553540000}'
    foreach ($hive in @(
        [Microsoft.Win32.RegistryHive]::CurrentUser,
        [Microsoft.Win32.RegistryHive]::LocalMachine
    )) {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            $hive, [Microsoft.Win32.RegistryView]::Registry32)
        try {
            $key = $root.OpenSubKey("SOFTWARE\Classes\CLSID\$clsid\InprocServer32")
            if ($null -ne $key) {
                try {
                    $path = [string]$key.GetValue('')
                    Info ("Flash ActiveX COM (32 bits, " + $hive + ")") $path
                    if ([string]::IsNullOrWhiteSpace($path)) {
                        Write-Warning 'La entrada de Flash COM esta vacia.'
                    } elseif (-not (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($path)))) {
                        Write-Warning 'La entrada de Flash COM apunta a un archivo que no existe.'
                    }
                    return $true
                } finally { $key.Dispose() }
            }
        } finally { $root.Dispose() }
    }
    Write-Warning 'No se encontro el CLSID ActiveX Flash de 32 bits en el registro.'
    return $false
}

$folder = (Resolve-Path -LiteralPath $ClientDirectory -ErrorAction Stop).ProviderPath
Write-Host '=== Diagnostico Redux / cliente Conquer 5065 (solo lectura) ==='
Info 'Carpeta' $folder
$exe = Join-Path $folder 'Conquer.exe'
$ocx = Join-Path $folder 'Flash.ocx'
$hook = Join-Path $folder 'CLHook.dll'
foreach ($path in @($exe, $ocx, $hook)) {
    $name = Split-Path $path -Leaf
    $present = Test-Path -LiteralPath $path -PathType Leaf
    Info $name $(if ($present) { 'Presente' } else { 'FALTA' })
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Info "$name CPU" (Read-ImageMachine $path)
        if ($name -eq 'Conquer.exe') {
            $clientHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            Info 'Conquer.exe SHA-256' $clientHash
            Info 'Conquer.exe compatible con login nativo' ($clientHash -eq '97CCC3276D46D46BB91AD62E758D1FB622C036F6224EED5EA7C121A80E550A89')
        }
        if ($name -eq 'Flash.ocx') {
            Info 'Flash.ocx SHA-256' ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            Info 'Flash.ocx firma' $signature.Status
            Info 'Flash.ocx version' ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion)
        }
    }
}

$configPath = Join-Path $folder 'config.json'
if (Test-Path -LiteralPath $configPath) {
    try {
        $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        Info 'Perfil version' $cfg.DefaultServer.ServerVersion
        Info 'Perfil Flash auto-fix DESACTIVADO' $cfg.DisableAutoFixFlash
        Info 'Modo de login' $(if ($cfg.UseOriginalFlashLogin) { 'Flash local (alternativo)' } else { 'Win32 nativo sin Flash' })
        Info 'Perfil ejecutable' $cfg.DefaultServer.ExecutableName
    } catch {
        Write-Warning 'No se pudo leer config.json (sin mostrar contenido).'
    }
} else {
    Write-Warning 'No existe config.json en la carpeta del cliente.'
}

$registered = Query-FlashRegistration
if (-not $registered) {
    Write-Host ''
    Write-Host 'RESULTADO: Falta el registro COM x86 de Flash. El hook que redirige'
    Write-Host 'LoadLibraryExW a Flash.ocx local NO crea por si mismo el registro COM.'
    Write-Host 'No registres Flash.ocx de 2007 en tu Windows principal; es software'
    Write-Host 'descontinuado y vulnerable. Para pruebas, usa un Windows aislado en VM'
    Write-Host 'sin red externa y solo con una copia confiable del cliente.'
}
$log = Join-Path $folder 'conquerloader.log'
if (Test-Path -LiteralPath $log) {
    Write-Host ''
    Write-Host '=== Ultimos eventos pertinentes del loader (sin credenciales) ==='
    $events = @(Get-Content -LiteralPath $log -Tail 130 |
        Where-Object { $_ -match '(?i)inject|flash|clhook|error|failed' } |
        Select-Object -Last 25)
    foreach ($eventText in $events) {
        $safe = $eventText -replace '(?i)(password|token|licensekey)\s*[:=]\s*\S+', '$1=[REDACTED]'
        Write-Host $safe
    }
}
Write-Host ''
Write-Host 'Fin del diagnostico. No se modifico el equipo.'
