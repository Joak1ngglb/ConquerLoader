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


## Modo experimental de login nativo sin Flash (5065 exacto)

A partir del commit de implementación del cliente, la rama incorpora
`ConquerHook/Flashless5065.cpp`. El launcher genera automáticamente
`FLASHLESS_NATIVE_LOGIN=1` en `CLHook.ini` para la versión 5065.

- Intercepta *solo* el cliente PE32 de 24-08-2008 que coincide con el
  timestamp, tamaño PE y bytes originales verificados.
- Evita la comprobación antigua de versión de Flash, e intenta capturar
  el objeto de login nativo del cliente.
- Presenta campos Windows de usuario y contraseña (contraseña ocultada).
  Los datos permanecen en RAM; no se guardan en ningún archivo ni servidor
  externo al cliente.
- Al pulsar Entrar, la rutina original del cliente intenta autenticar
  contra Redux, conservando el protocolo de red del juego.
- No instala, registra ni carga `Flash.ocx` para el login nativo.

**Estado actual:** el login nativo es el modo predeterminado, se inyecta antes
del entry point y valida el SHA-256 exacto
`97CCC3276D46D46BB91AD62E758D1FB622C036F6224EED5EA7C121A80E550A89`
antes de aplicar cualquier RVA. La compilación y las pruebas de regresión
pasan; todavía falta la prueba real con ese `Conquer.exe` y un servidor Redux
activo para confirmar autenticación y entrada al juego.

Prueba: hacé una copia de la carpeta original, copiá encima el *paquete
completo* de ConquerLoader de la rama y abrí `ConquerLoader.exe`.
Debería aparecer una ventana adicional `Redux 5065 - Sin Adobe Flash`.
Si muestra «Esperando el login interno», el cliente no alcanzó la
inicialización esperada y requiere un cambio posterior en esa ruta.
Si el juego se cierra, anotá el mensaje/log; no vuelvas a registrar Flash.

**Rollback:** cerrá el cliente y recuperá la carpeta original respaldada.
Si se deshabilita `FLASHLESS_NATIVE_LOGIN`, vuelve el comportamiento anterior.

**Limitación de versión:** nunca aplicar a un Conquer.exe diferente.
No modificar `Conquer.exe` en disco ni publicar sus archivos en Git.


## Estado OFFLINE en el launcher

La pantalla de inicio de sesión Win32 `Listo para autenticar con Redux`
solo confirma que está enlazado el objeto del cliente con el hook. **NO**
confirma que Redux esté escuchando en los puertos, ni que el login funcione.
El status del launcher muestra por separado los probes TCP de
`LoginHost:LoginPort` (habitualmente 127.0.0.1:9958) y
`GameHost:GamePort` (habitualmente 127.0.0.1:5816). En estado OFFLINE,
comprobar el servidor Redux y su archivo `NOMBRE-PC.ini`; no ingresar
contraseñas reales en el login experimental. Las pruebas TCP no implican
compatibilidad de protocolo.

En Windows PowerShell:

```powershell
Test-NetConnection 127.0.0.1 -Port 9958
Test-NetConnection 127.0.0.1 -Port 5816
```

## Ventana de Conquer colapsada en una franja horizontal

El login sin Flash ya reconoce la estructura de autenticación, pero no
recrea automáticamente la UI SWF del cliente. A veces la ventana gráfica de
Conquer.exe aparece como una franja horizontal (aprox. 800x20) en lugar de
800x600. El módulo de login comprueba el rectángulo de la ventana real,
excluye ventanas auxiliares y únicamente si está claramente colapsada
intenta recuperar el viewport a 800x600, una sola vez. En el login nativo
se informa el tamaño detectado, o que la ventana continúa colapsada.

**Esta recuperación no sustituye el contenido Flash**: puede quedar la
ventana completa negra hasta que funcione la autenticación con Redux.
La ventana nativa separada contiene los campos de login. Si aparece
'Ventana del juego colapsada', no ingresar claves y verificar ventana,
hooks y renderizador. Si el estado del launcher es OFFLINE, iniciar Redux y
comprobar los puertos 9958/5816.

El ajuste solo se aplica al Conquer.exe exacto para el que el hook valida
timestamp y bytes; no toca el ejecutable del disco.


## Volver al Flash original con runtime con soporte (2026)

La configuración ahora admite `UseOriginalFlashLogin`:

- `true`: alternativa que conserva el formulario SWF y usa `Flash.ocx` local
  mediante redirección y class factory sin registro COM global.
- `false`: login Win32 nativo sin cargar ni registrar `Flash.ocx`.

El perfil incluido en el ZIP usa `UseOriginalFlashLogin=false`. El modo Flash
queda únicamente como fallback manual y no debe probarse fuera de una VM con
un OCX x86 de procedencia confiable.

Wipro Engineering (anteriormente HARMAN DTS) informa soporte comercial
para Flash Player versión 50.0 bajo licencia especial; la disponibilidad
de un ActiveX x86 compatible con Conquer 5065 **debe confirmarla el
proveedor**. El AIR SDK NO reemplaza `Flash.ocx`; Ruffle NO es un control
ActiveX que pueda instalarse directamente dentro del juego.
Documentación oficial: https://airsdk.harman.com/faq
Contacto publicado: adobe.support@wipro.com

Para crear un perfil original:
```powershell
.\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer Online' -LoginMode Flash -Force
```

Para volver al modo nativo experimental, sin cambiar ningún binario:
```powershell
.\tools\Configure-Redux5065.ps1 -ClientDirectory 'C:\Juegos\Conquer Online' -LoginMode Native -Force
```

También se puede editar directamente `config.json`, con el juego cerrado.
**No instalar Flash antiguo de sitios no oficiales** ni crear exclusiones
de antivirus. El modo original Flash depende de una licencia válida y un
ActiveX compatible: compilar ConquerLoader no garantiza esa compatibilidad.


## Flash local x86 al estilo Ultimation (implementación con fallback COM)

El artículo de Ultimation (2021) redirige `LoadLibraryExW` a
`Flash.ocx` situado en la carpeta del cliente. El código anterior de
`UseOriginalFlashLogin=true` anulaba accidentalmente esa redirección y
exigía un Flash registrado en Windows. **Corregido.**

Ahora el modo `UseOriginalFlashLogin=true`:

1. Busca `Flash.ocx` junto a `Conquer.exe`.
2. Habilita el gancho local de `LoadLibraryExW` como en el artículo.
3. Para cuando el ActiveX no esté registrado, intenta resolver
   `CLSIDFromProgID`, `CoGetClassObject` y `CoCreateInstance` directamente
   desde el `DllGetClassObject` exportado por el OCX local.
4. Deja que el SWF original dibuje su login, **sin** inyectar la ventana
   nativa experimental ni modificar `Conquer.exe` en disco.
5. No escribe en el registro de Windows ni registra controles antiguos.

**Límites conocidos:** la inicialización de COM por un OCX puede depender
de otras claves del registro; el desvío de clase no garantiza compatibilidad
ni arranque. Si `ole32.dll` todavía no está cargado cuando se instala el
gancho, el fallback COM podría no entrar en acción. Revisar el log antes de
afirmar éxito. El cliente debe probarse contra Redux para confirmar login.

El `Flash.ocx` que recibió originalmente el usuario era 7.0.14.0,
de 32 bits y sin firma. **No lo uses en el Windows principal**: cualquier
control ActiveX cargado ejecuta código en el proceso y los antiguos tienen
vulnerabilidades conocidas. Para probar la técnica usar una VM aislada
con instantánea y un archivo OCX de procedencia verificada; el ZIP no
distribuye componentes Flash de terceros.

Fuente: https://www.elitepvpers.com/forum/co2-guides-templates/4858018-release-flash-fix-old-clients.html


## Cambio esencial de Dragon: instalar el hook ANTES del entry point

Se verificó `Dragon.Launch/launch_process.cpp` y `Dragon.Module.Flash/flash_hook.cpp`
del repositorio de Spirited. El detour de Flash es casi idéntico al de
Ultimation, pero Dragon crea `Conquer.exe` suspendido, programa la carga
con `QueueUserAPC(LoadLibraryW)` y reanuda su hilo principal. En el
ConquerLoader anterior la DLL se inyectaba después de `Process.Start`,
cuando ya podía haber fallado la inicialización de Flash.

Nuestra implementación `EarlyInjectedClient.cs` usa el mismo orden para
**ambos modos** de Conquer 5065:

1. Iniciar el ejecutable con `CREATE_SUSPENDED` (x86).
2. Copiar la ruta absoluta de `CLHook.dll` al proceso.
3. Programar `LoadLibraryW` con `QueueUserAPC` en el hilo primario.
4. Reanudar Conquer, verificar que `CLHook.dll` se cargó y no volver a
   inyectarlo por segunda vez.
5. Si no hay carga confirmada, interrumpir esa prueba; no arrancar un
   proceso sin el hook.

**No significa que el Flash 7.0.14.0 sin firma sea seguro o compatible.**
No se incluye Flash.ocx en el ZIP. El control requiere evaluación en VM,
preferentemente con un archivo legítimo de arquitectura x86 compatible.
El inicio completo del cliente sigue sin estar verificado: el build solo
confirma compilación y lógica de infraestructura de arranque.

Referencia: https://gitlab.com/spirited/dragon/


## Crash al llegar a 100% (inicio temprano)

Se descubrió un fallo de secuencia: al inyectar `CLHook.dll` desde
`QueueUserAPC` antes del entry point, el antiguo `csv3_init` llamaba
`CreateHook32(GetProcAddress(ws2_32.dll, connect), ...)` aunque la DLL
Winsock todavía podía no estar lista. El viejo `CreateHook32` no valida
`NULL` y ejecuta `memcmp` sobre esa dirección, con riesgo de cierre
inmediato del cliente. En modo nativo la nueva versión no instala hooks Flash;
difiere `connect`, `send` y `_snprintf` hasta que `ws2_32.dll` y `msvcr90.dll`
estén cargadas, y usa trampolines Detours en lugar del parche de cinco bytes.

El progreso **100% pertenece al launcher**, no confirma que el juego esté
visible. Para investigar, el log `CLHook-5065.log` muestra si la DLL se
cargó y si el hook de red se instaló. `conquerloader.log` registra el código
de salida de Conquer.exe; el launcher permanece abierto si falla la versión
5065, para que pueda verse el error. No introducir contraseñas reales hasta
confirmar la pantalla original.

La advertencia de Flash 7.0.14.0 que muestra ConquerLoader es una advertencia
de seguridad **del launcher**, distinta de «Please install Flash 6.0 or above»
del ejecutable. El OCX 7 antiguo no se vuelve seguro porque cargue.


## Crash aislado por etapas — ExitCode 0xC0000005

El error `0xC0000005` es una infracción de acceso a memoria. El hecho de
que `CLHook.dll` haya aparecido en los módulos de Conquer.exe no significa
que el juego ni el OCX estén inicializados. Las pruebas de compilación **no**
son pruebas de ejecución real en Windows con el cliente 5065.

Se añadió `Flash5065DiagnosticMode` a `config.json`, aplicable únicamente
al inicio temprano del cliente 5065 con `UseOriginalFlashLogin=true`.

| Valor | Hook Flash LoadLibrary | Fallback COM | Hook Winsock |
|---|---|---|---|
| 0 | Sí | Sí | Sí (normal, experimental) |
| 1 | Sí | Sí | No, aislado |
| 2 | Sí | No | No |
| 3 | No | No | No; solo carga CLHook |

Con el juego cerrado y copia de seguridad, el orden de prueba es 1, 2, 3.
Usar únicamente una VM aislada para ejecutar Flash 7 sin firma. En 1/2/3
no esperes poder conectar al servidor: se está diagnosticando la pantalla
Flash, no el networking. No ingreses contraseñas reales.

El archivo `CLHook-5065.log` distingue etapas. El script
`Diagnose-Crash5065.ps1` consulta ese log, `conquerloader.log` y los
eventos Application Error ID 1000 de Windows para registrar el módulo
que falla, sin alterar el registro ni subir datos automáticamente.

En PowerShell dentro de la carpeta del cliente:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\\Diagnose-Crash5065.ps1
```

**Importante:** evitar varias instancias de Conquer.exe; el registro del
usuario mostraba dos. Ejecutar con una copia del cliente y su Flash.ocx
solo dentro de una VM o entorno de prueba aislado.
