#Requires -Version 5.1
<#
  Read-only Conquer 5065 crash report: no DLL loading, injections, registry
  writes, script installation or automatic uploading.
#>
[CmdletBinding()]
param([string]$ClientDirectory=$PSScriptRoot)
$ErrorActionPreference = 'Stop'
$folder=(Resolve-Path -LiteralPath $ClientDirectory).Path
Write-Host "=== Conquer.exe crash diagnostics ==="
Write-Host "Folder: $folder"
$hookLines=@()
foreach($filename in @('CLHook-5065.log','conquerloader.log')){
    $file=Join-Path $folder $filename
    if(Test-Path -LiteralPath $file){
        Write-Host "=== $filename (last 45 lines) ==="
        $lines=@(Get-Content -LiteralPath $file -Tail 120)
        if($filename -eq 'CLHook-5065.log'){$hookLines=$lines}
        $lines | Select-Object -Last 45 | ForEach-Object {
            $_ -replace '(?i)(password|token|licensekey)\s*[:=]\s*\S+', '$1=[REDACTED]'
        }
    }else{Write-Host "$filename : not found"}
}
Write-Host '=== Flash activation summary ==='
if($hookLines.Count -eq 0){
    Write-Host 'No CLHook stage data available.'
}else{
    $lastStage=$hookLines | Where-Object {$_ -match '\[flash:([^\]]+)\]'} | Select-Object -Last 1
    $lastHr=$hookLines | Where-Object {$_ -match 'HRESULT=0x[0-9A-Fa-f]{8}'} | Select-Object -Last 1
    $lastException=$hookLines | Where-Object {$_ -match 'EXCEPTION code='} | Select-Object -Last 1
    Write-Host ('Last Flash stage: ' + $(if($lastStage){$lastStage}else{'not recorded'}))
    Write-Host ('Last HRESULT: ' + $(if($lastHr){$lastHr}else{'not recorded'}))
    Write-Host ('Last exception: ' + $(if($lastException){$lastException}else{'not recorded'}))
    foreach($required in @(
        'LoadLibraryExW and COM activation hooks committed atomically.',
        'Flash.ocx loaded at',
        'Preflight complete: local ShockwaveFlash class factory ready.'
    )){
        Write-Host ("Checkpoint '$required': " + [bool]($hookLines -match [regex]::Escape($required)))
    }
}
Write-Host '=== Binary identity ==='
foreach($name in @('Conquer.exe','Flash.ocx','CLHook.dll')){
    $path=Join-Path $folder $name
    if(Test-Path -LiteralPath $path -PathType Leaf){
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion
        Write-Host "$name SHA256=$hash Version=$version"
    }else{Write-Host "$name MISSING"}
}
Write-Host "=== Application Error (event id 1000), last 24h ==="
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Application'; Id=1000; StartTime=(Get-Date).AddHours(-24)
    } -ErrorAction Stop | Where-Object { $_.Message -match '(?i)Conquer\.exe' } |
        Select-Object -First 4)
    if($events.Count -eq 0){Write-Host 'No Windows event for Conquer.exe.'}
    foreach($e in $events) {
        Write-Host "--- $($e.TimeCreated) ---"
        $e.Message -split '\r?\n' | Where-Object {
            $_ -match '(?i)conquer.exe|fault|error|exception|faulting|modulo|aplicaci|c[óo]digo|desplazamiento|ruta|offset|0xc0000005'
        } | ForEach-Object { Write-Host $_ }
    }
}catch{Write-Warning 'Windows events unavailable; logs above are still useful.'}
Write-Host 'Read-only diagnostic finished.'
