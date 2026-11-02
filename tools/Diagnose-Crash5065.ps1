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
foreach($filename in @('CLHook-5065.log','conquerloader.log')){
    $file=Join-Path $folder $filename
    if(Test-Path -LiteralPath $file){
        Write-Host "=== $filename (last 45 lines) ==="
        Get-Content -LiteralPath $file -Tail 45 | ForEach-Object {
            $_ -replace '(?i)(password|token|licensekey)\\s*[:=]\\s*\\S+', '$1=[REDACTED]'
        }
    }else{Write-Host "$filename : not found"}
}
Write-Host "=== Application Error (event id 1000), last 24h ==="
try {
    $events=@(Get-WinEvent -FilterHashtable @{
        LogName='Application'; Id=1000; StartTime=(Get-Date).AddHours(-24)
    } -ErrorAction Stop | Where-Object { $_.Message -match '(?i)Conquer\\.exe' } |
        Select-Object -First 4)
    if($events.Count -eq 0){Write-Host 'No Windows event for Conquer.exe.'}
    foreach($e in $events) {
        Write-Host "--- $($e.TimeCreated) ---"
        $e.Message -split "`r?`n" | Where-Object {
            $_ -match '(?i)conquer.exe|fault|error|exception|faulting|modulo|aplicaci|c[óo]digo|desplazamiento|ruta|offset|0xc0000005'
        } | ForEach-Object { Write-Host $_ }
    }
}catch{Write-Warning 'Windows events unavailable; logs above are still useful.'}
Write-Host 'Read-only diagnostic finished.'
