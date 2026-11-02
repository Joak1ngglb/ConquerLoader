#Requires -Version 5.1
<#
.SYNOPSIS
  Genera config.json de ConquerLoader para Redux y el cliente ingles 5065.
.DESCRIPTION
  Solo escribe el perfil de conexion del loader. No ejecuta juegos, no modifica
  DLLs, antivirus, TQAT.exe ni archivos del servidor Redux.
.EXAMPLE
  .\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer5065'
.EXAMPLE
  .\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer5065' -LoginIp '192.168.1.50' -GameIp '192.168.1.50' -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientDirectory,

    [string]$LoginIp = '127.0.0.1',
    [string]$GameIp = '',
    [ValidateRange(1, 65535)][int]$LoginPort = 9958,
    [ValidateRange(1, 65535)][int]$GamePort = 5816,
    [ValidateNotNullOrEmpty()][string]$ServerName = 'Redux_Beta',
    [ValidateSet('Flash','Native')][string]$LoginMode = 'Flash',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-IPv4 {
    param([string]$Value, [string]$Field)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$parsed) -or
        $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -eq '0.0.0.0') {
        throw "$Field debe ser una direccion IPv4 de destino valida (no 0.0.0.0): $Value"
    }
}

if ([string]::IsNullOrWhiteSpace($GameIp)) {
    $GameIp = $LoginIp
}
Assert-IPv4 -Value $LoginIp -Field 'LoginIp'
Assert-IPv4 -Value $GameIp -Field 'GameIp'

$client = (Resolve-Path -LiteralPath $ClientDirectory -ErrorAction Stop).ProviderPath
if (-not (Test-Path -LiteralPath (Join-Path $client 'Conquer.exe') -PathType Leaf)) {
    throw "No se encontro Conquer.exe en $client. Indicá la carpeta raiz del cliente 5065."
}
if (-not (Test-Path -LiteralPath (Join-Path $client 'ConquerLoader.exe') -PathType Leaf)) {
    Write-Warning 'No se encontro ConquerLoader.exe en la carpeta. Copia primero los archivos compilados del loader.'
}

$configPath = Join-Path $client 'config.json'
$encryptedPath = Join-Path $client 'config.json.lock'
if (Test-Path -LiteralPath $encryptedPath -PathType Leaf) {
    throw "Existe config.json.lock (tiene prioridad sobre config.json). No se modifico nada. Retira/configura manualmente ese perfil cifrado."
}
if ((Test-Path -LiteralPath $configPath -PathType Leaf) -and -not $Force) {
    throw "Ya existe config.json en $client. No se sobrescribio. Usa -Force para guardar una copia de seguridad y reemplazarlo."
}

# Mantener Group no nulo: el loader agrupa servidores mediante Server.Group.
$server = [ordered]@{
    ServerName = $ServerName
    ServerVersion = 5065
    LoginHost = $LoginIp
    GameHost = $GameIp
    LoginPort = $LoginPort
    GamePort = $GamePort
    ExecutableName = 'Conquer.exe'
    EnableHostName = $false
    UseDirectX9 = $false
    Hostname = ''
    ServerNameMemoryAddress = '0'
    ServerIcon = ''
    Group = [ordered]@{
        GroupName = ''
        GroupIcon = ''
        Servers = @()
    }
}
$config = [ordered]@{
    Servers = @($server)
    DefaultServer = $server
    DebugMode = $false
    CloseOnFinish = $false
    HighResolution = $false
    FHDResolution = $false
    FullScreen = $false
    ServernameChange = $false
    DisableAutoFixFlash = $false
    UseOriginalFlashLogin = ($LoginMode -eq 'Flash')
    Flash5065DiagnosticMode = 1
    Title = 'Redux 5065 local'
    Description = 'Conquer Online 5065 - Redux'
    Lang = 'es'
    LicenseKey = ''
    DisableScreenChanges = $true
    UseCustomDLLs = $false
    FPSUnlock = $false
}

$json = $config | ConvertTo-Json -Depth 12
# Verificacion previa: el contenido generado debe ser JSON parseable y version 5065.
$parsed = $json | ConvertFrom-Json
if ($parsed.Servers.Count -ne 1 -or $parsed.Servers[0].ServerVersion -ne 5065) {
    throw 'El perfil generado no supero la validacion.'
}

if ($PSCmdlet.ShouldProcess($configPath, 'Guardar configuracion Redux 5065')) {
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $backupPath = Join-Path $client ("config.json.backup-" + $stamp)
        Copy-Item -LiteralPath $configPath -Destination $backupPath -ErrorAction Stop
        Write-Host "Copia de seguridad: $backupPath"
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($configPath, $json + [Environment]::NewLine, $utf8NoBom)
    Write-Host "Perfil Redux 5065 configurado: $configPath"
    Write-Host "Login: $($LoginIp):$LoginPort | Juego: $($GameIp):$GamePort"
    Write-Host 'Inicia el servidor Redux antes del cliente. No desactives Windows Defender.'
}
