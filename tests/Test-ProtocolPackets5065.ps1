#Requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$hook=Get-Content -LiteralPath (Join-Path $root 'ConquerHook/CLHook.cpp') -Raw
function Assert([bool]$ok,[string]$reason){if(-not $ok){throw $reason}}
function Hex([byte[]]$bytes){[BitConverter]::ToString($bytes).Replace('-','')}

# Source of truth: Joak1ngglb/redux-co Redux/Packets/Login/[1086]Account.cs.
Assert ($hook.Contains('Size=52, AccountOffset=4, PasswordRc5Offset=20, ServerOffset=36, FieldSize=16')) 'Redux AccountEx layout changed.'
Assert ($hook.Contains('ReduxGameConnect5065 { enum { Size=28, Type=1052 }')) 'Redux MsgConnect layout changed.'

# Synthetic packet only: no real account or credential data.
$packet=New-Object byte[] 52
[BitConverter]::GetBytes([uint16]52).CopyTo($packet,0)
[BitConverter]::GetBytes([uint16]1051).CopyTo($packet,2)
for($i=0;$i -lt 16;$i++){
    $packet[4+$i]=[byte](0x40+$i)       # account fixture
    $packet[20+$i]=[byte](0xC0+$i)     # opaque RC5 ciphertext fixture
    $packet[36+$i]=[byte](0x60+$i)     # server fixture
}
$original=[byte[]]$packet.Clone()

# Reproduce the documented TQ auth transport cipher and lock it to a vector
# independently matching Redux AuthCryptographer.Key1/Key2.
$p=[byte[]](0x9D,0x0F,0xFA,0x13); $g=[byte[]](0x62,0x79,0x5C,0x6D)
$iv=New-Object byte[] 512
for($i=0;$i -lt 256;$i++){
    $iv[$i]=$p[0]; $iv[$i+256]=$g[0]
    $p[0]=[byte]((([int]$p[1]+([int]$p[0]*[int]$p[2]))*[int]$p[0]+[int]$p[3])-band 255)
    $g[0]=[byte]((([int]$g[1]-([int]$g[0]*[int]$g[2]))*[int]$g[0]+[int]$g[3])-band 255)
}
Assert ((Hex ($iv[0..15])) -eq '9D90838AD18CE7F62528EB8299648F2E') 'Auth Key1 vector mismatch.'
Assert ((Hex ($iv[256..271])) -eq '624FE815DEEB04911AC7E04D16E37C49') 'Auth Key2 vector mismatch.'

$encrypted=New-Object byte[] 52
for($i=0;$i -lt 52;$i++){
    $b=$packet[$i] -bxor $iv[$i] -bxor $iv[256]
    $b=(($b -shr 4) -bor (($b -shl 4)-band 255))
    $encrypted[$i]=[byte]($b -bxor 0xAB)
}
$decrypted=New-Object byte[] 52
for($i=0;$i -lt 52;$i++){
    $b=$encrypted[$i] -bxor 0xAB
    $b=(($b -shr 4) -bor (($b -shl 4)-band 255))
    $decrypted[$i]=[byte]($b -bxor $iv[$i] -bxor $iv[256])
}
Assert ((Hex $decrypted) -eq (Hex $original)) 'Auth transport round-trip changed AccountEx bytes.'
Assert ((Hex ($decrypted[20..35])) -eq (Hex ($original[20..35]))) 'Opaque RC5 password block was modified.'

# Server-to-client uses the inverse direction. Redux Encrypt applies AB/swap/key;
# CLegacyCipher::Encrypt reverses it on the observer's private copy.
$response=[byte[]](32,0,31,4)
$serverWire=New-Object byte[] 4
$clientObserved=New-Object byte[] 4
for($i=0;$i -lt 4;$i++){
    $b=$response[$i] -bxor 0xAB
    $b=(($b -shr 4) -bor (($b -shl 4)-band 255))
    $serverWire[$i]=[byte]($b -bxor $iv[$i] -bxor $iv[256])
}
for($i=0;$i -lt 4;$i++){
    $b=$serverWire[$i] -bxor $iv[$i] -bxor $iv[256]
    $b=(($b -shr 4) -bor (($b -shl 4)-band 255))
    $clientObserved[$i]=[byte]($b -bxor 0xAB)
}
Assert ((Hex $clientObserved) -eq (Hex $response)) 'Server-to-client 1055 observer direction is wrong.'
Assert ($hook.Contains('g_authInboundObserver5065->Encrypt(observed,result)')) 'Inbound observer must use the inverse auth direction.'
Write-Host 'OK: Redux 52-byte AccountEx layout, 28-byte MsgConnect metadata and auth cipher vectors verified without credentials.'
