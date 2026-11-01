# ConquerLoader + Redux: perfil de cliente 5065

Preparado para Joak1ngglb/redux-co con un cliente ingles Conquer Online 5065 y ConquerLoader de este repositorio.

## Parametros de red verificados

Redux/ConfigCreatorForm.cs genera un INI llamado NOMBRE_DEL_EQUIPO.ini con estos valores (GAME_IP y SERVER_NAME se eligen al configurarlo):

    [GENERAL]
    SERVER_NAME=Redux_Beta
    GAME_IP=127.0.0.1
    LOGIN_PORT=9958
    GAME_PORT=5816

Importante: Redux/Constants.cs inicia LOGIN_PORT en 9959, pero Redux/Database/Readers/SettingsReader.cs lee y reemplaza ese valor desde el INI antes de abrir los sockets. Por eso, **el INI real de Redux tiene prioridad**. Cuando se usa el generador del servidor, el login es 9958 y el juego es 5816.

El GAME_IP del INI tiene que ser una IP alcanzable por el cliente. No uses 0.0.0.0 como destino de conexion.

### Valores del perfil local

    Cliente: Conquer Online 5065 (ingles)
    ServerName: Redux_Beta
    LoginHost: 127.0.0.1
    GameHost: 127.0.0.1
    LoginPort: 9958
    GamePort: 5816
    ExecutableName: Conquer.exe
    UseDirectX9: false
    ServernameChange: false
    DisableScreenChanges: true

El modo de hook del loader se elige automaticamente por version. Para 5065 (<5717), la documentacion del proyecto identifica CLHook.dll, no el modo de server.dat descifrado de las versiones posteriores.

## Preparar ConquerLoader

1. Compila ConquerLoader/ConquerLoader.sln en Visual Studio con configuracion Release y .NET Framework 4.6.2. El launcher genera binarios x86 incluso usando la plataforma de solucion Any CPU.
2. Copia **todo el contenido de la carpeta compilada** (normalmente ConquerLoader/Release, incluidas las DLL necesarias) a la raiz de una copia de prueba del cliente 5065, junto a Conquer.exe.
3. Desde PowerShell en la raiz de este repositorio ejecuta:

    .\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer5065'

La herramienta genera config.json para Redux local. Antes de escribir comprueba que existe Conquer.exe; si falta ConquerLoader.exe muestra una advertencia. No reemplaza un config.json existente a menos que agregues -Force, y en ese caso primero crea una copia de seguridad. Se detiene si existe config.json.lock porque el loader le da prioridad a esa configuracion cifrada.

Alternativamente, para la configuracion local exacta, copia profiles/redux-5065.local.json como config.json a la raiz del cliente.

### Cuando Redux esta en otra PC

    .\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer5065' -LoginIp '192.168.1.50' -GameIp '192.168.1.50' -LoginPort 9958 -GamePort 5816 -ServerName 'Redux_Beta'

Reemplaza 192.168.1.50 por la IP real del servidor. El GAME_IP del INI del servidor Redux tiene que ser alcanzable desde el equipo del cliente; Redux lo envia luego de autenticar. Tambien puedes agregar -WhatIf (simulacion sin escribir) o -Force (respaldo y reemplazo del config.json existente).

## Probar conexion

1. Inicia Redux con su INI, base de datos y dependencias correctamente configurados.
2. En el equipo del cliente ejecuta en PowerShell:

    Test-NetConnection 127.0.0.1 -Port 9958
    Test-NetConnection 127.0.0.1 -Port 5816

3. Si el servidor es remoto, sustituye 127.0.0.1 por su IP.
4. Inicia ConquerLoader.exe desde la carpeta del cliente y selecciona Redux_Beta.

Un resultado TCP positivo solo confirma que hay un servicio escuchando; no demuestra que el protocolo entre cliente y Redux sea compatible.

## Seguridad

El script no ejecuta Conquer.exe, ConquerLoader.exe ni TQAT.exe, no cambia DLLs ni archivos del cliente, no hace autopatch y no deshabilita Windows Defender. El cliente 5065 y las DLL de redireccion deben verificarse en un entorno aislado antes de ejecutarse en una PC principal. No otorgues exclusiones de antivirus solo para evitar alertas.

Los archivos del cliente comercial no forman parte de esta configuracion ni del repositorio.

## Prueba automatizada del perfil

Desde PowerShell:

    .\tests\Test-Redux5065.ps1

Esta prueba utiliza una carpeta temporal con archivos ficticios para los nombres del cliente y del loader, sin ejecutarlos.


## Diagnóstico real del Conquer.exe 5065 (24/08/2008)

Análisis estático del ejecutable aportado por el usuario, SHA-256:
`97ccc3276d46d46bb91ad62e758d1fb622c036f6224eed5ea7c121a80e550a89`.
PE32/i386, contiene referencias a `CShockwaveFlash`,
`DlgLoginFlash.cpp` y `Flash.ocx`, ejecuta la verificación ActiveX.
En la función cercana a 0x0047A0B1 hay una comparación con 0x00060000
(versión mínima 6.0); si falla, en la ruta próxima a 0x0047A2A1,
construye un comando de `regsvr32 /s Flash.ocx`.
No es solo el launcher Play.exe; el cliente usa COM Flash realmente.

**Corrección de ruteo de ConquerLoader:** antes `useDecryptedServerDat`
era true siempre y se intentaba `COFlashFixer.dll` para la versión 5065,
aunque esta DLL solo se generaba para >=5717. Ahora 5065 usa `CLHook.dll`
de código nativo, y el perfil habilita `DisableAutoFixFlash=false`.
El workflow recompila el CLHook con CFlashFix desde el proyecto C++ en vez de
confiar en la DLL legacy de recurso antigua.

**Límite:** incluso con hook, si el ActiveX Flash no está registrado en el
sistema, la creación COM puede fallar antes de que el hook de `LoadLibraryExW`
intercepte nada. No se ha verificado el inicio real en Windows con el OCX del
usuario. Evitar registrar Flash antiguo en Windows principal. Usar entorno
virtual y evaluar un reemplazo de login sin Flash a largo plazo.

No modificar `Conquer.exe` en disco; el parche solo afecta el flujo
 del launcher. Mantener rutas y hashes separados para pruebas.


## Diagnóstico del Flash que sigue fallando

El ZIP incluye el script solo lectura `Diagnose-Flash5065.ps1`.
Ejecutar desde la carpeta del cliente en PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Diagnose-Flash5065.ps1
```

Verifica arquitectura x86 del cliente/OCX/CLHook, si hay registro COM
Flash de **32 bits**, firma/versión/hash del Flash.ocx existente,
config.json e incidencias de `conquerloader.log`. No registra nada.

**Problema subyacente:** el cliente 5065 no solo abre `Flash.ocx`
como DLL: crea un control COM `CShockwaveFlash`. El hook CLHook
solo intercepta una llamada a `LoadLibraryExW`; si COM no está registrado,
el hook no resuelve la activación de ese control. El uso seguro de un
ActiveX de 2007 en el host no es recomendable. El diagnóstico distingue
esto de una inyección CLHook fallida.
