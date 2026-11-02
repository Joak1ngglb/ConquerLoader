#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$configure = Join-Path $root 'tools\Configure-Redux5065.ps1'
$template = Join-Path $root 'profiles\redux-5065.local.json'
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('redux-5065-test-' + [guid]::NewGuid().ToString('N'))

function Assert {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

try {
    New-Item -ItemType Directory -Path $tempDir -ErrorAction Stop | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $tempDir 'Conquer.exe'), 'test only')
    [System.IO.File]::WriteAllText((Join-Path $tempDir 'ConquerLoader.exe'), 'test only')

    $sample = Get-Content -LiteralPath $template -Raw | ConvertFrom-Json
    Assert ($sample.Servers.Count -eq 1) 'La plantilla tiene que contener un solo servidor.'
    Assert (-not $sample.DisableAutoFixFlash) 'El perfil permite el hook legacy en modo nativo.'
    Assert ($sample.UseOriginalFlashLogin -eq $true) 'El perfil actual debe ofrecer Flash original.'
    Assert ($sample.DefaultServer.ServerVersion -eq 5065) 'Version incorrecta en plantilla.'
    Assert ($sample.Servers[0].LoginPort -eq 9958) 'Puerto login incorrecto en plantilla.'
    Assert ($sample.Servers[0].GamePort -eq 5816) 'Puerto juego incorrecto en plantilla.'
    Assert ($sample.Servers[0].Group -ne $null) 'El grupo de servidor no puede ser nulo.'

    & $configure -ClientDirectory $tempDir -WhatIf | Out-Null
    Assert (-not (Test-Path (Join-Path $tempDir 'config.json'))) '-WhatIf escribio un archivo.'

    & $configure -ClientDirectory $tempDir | Out-Null
    $configPath = Join-Path $tempDir 'config.json'
    $current = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    Assert ($current.Servers.Count -eq 1) 'La configuracion generada tiene varios servidores.'
    Assert (-not $current.DisableAutoFixFlash) 'El configurador cambio el hook antiguo.'
    Assert ($current.UseOriginalFlashLogin -eq $true) 'La configuracion original no habilito Flash.'
    Assert ($current.Servers[0].ServerVersion -eq 5065) 'La configuracion no es 5065.'
    Assert ($current.Servers[0].LoginHost -eq '127.0.0.1') 'IP de login local incorrecta.'
    Assert ($current.DefaultServer.LoginPort -eq 9958) 'Puerto de login incorrecto.'
    Assert ($current.Servers[0].GamePort -eq 5816) 'Puerto de juego incorrecto.'
    Assert ($current.Servers[0].Group -ne $null) 'Group no debe ser null.'

    $refused = $false
    try {
        & $configure -ClientDirectory $tempDir | Out-Null
    } catch {
        $refused = $true
    }
    Assert $refused 'No se debe reemplazar un config.json existente sin -Force.'

    & $configure -ClientDirectory $tempDir -Force -LoginIp '192.168.1.50' -GameIp '192.168.1.51' -LoginPort 9959 -GamePort 5817 | Out-Null
    $updated = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    Assert ($updated.DefaultServer.LoginHost -eq '192.168.1.50') 'No guardo IP de login personalizada.'
    Assert ($updated.DefaultServer.GameHost -eq '192.168.1.51') 'No guardo IP de juego personalizada.'
    Assert ($updated.DefaultServer.LoginPort -eq 9959) 'No guardo puerto login personalizado.'
    Assert ($updated.DefaultServer.GamePort -eq 5817) 'No guardo puerto juego personalizado.'
    $backups = @(Get-ChildItem -LiteralPath $tempDir -Filter 'config.json.backup-*')
    Assert ($backups.Count -eq 1) 'Se esperaba exactamente un respaldo.'
    $backup = Get-Content -LiteralPath $backups[0].FullName -Raw | ConvertFrom-Json
    Assert ($backup.DefaultServer.LoginPort -eq 9958) 'El respaldo no conserva los puertos anteriores.'


    & $configure -ClientDirectory $tempDir -Force -LoginMode Native | Out-Null
    $native = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    Assert ($native.UseOriginalFlashLogin -eq $false) 'No permite volver al modo nativo.'
    [System.IO.File]::WriteAllText((Join-Path $tempDir 'config.json.lock'), 'test only')
    $refusedLocked = $false
    try {
        & $configure -ClientDirectory $tempDir -Force | Out-Null
    } catch {
        $refusedLocked = $true
    }
    Assert $refusedLocked 'Debe rechazar un config.json.lock existente.'
    Write-Host 'PASS: perfil Redux 5065, validacion, WhatIf, respaldo y bloqueo de config cifrada.'
}
finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
