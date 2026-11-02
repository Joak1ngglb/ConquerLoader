# Auditoría del login Redux 5065

Referencia auditada: `Joak1ngglb/redux-co` commit
`850c9430743dd9ab59b226a6795243afbb619c74`.

## Paquete de cuenta

Redux descifra primero el transporte en `LoginServer.Auth_OnReceive`. Después
acepta el tipo 1051 y convierte el buffer mediante
`Packets/Login/[1086]Account.cs`. El nombre del archivo no es el tipo de paquete
usado por ese `switch`.

El contrato consumido por Redux ocupa exactamente 52 bytes:

| Offset | Longitud | Campo |
|---:|---:|---|
| 0 | 2 | longitud, 52 |
| 2 | 2 | tipo, 1051 |
| 4 | 16 | cuenta |
| 20 | 16 | contraseña cifrada con RC5 |
| 36 | 16 | servidor |

El cliente original ya entrega este bloque protegido. `CLHook.dll` no lee,
registra, descifra, modifica ni vuelve a cifrar esos campos. El hook de `send`
sólo registra longitud, ruta, peer y resultado, y reenvía el mismo puntero y
longitud al trampoline de Winsock.

## Envío de 28 bytes

Redux define `MSG_CONNECT = 1052`. `Packets/Game/[1052]Connect.cs` serializa 28
bytes y `GameServer` procesa ese tipo para asociar cuenta y token después del
handshake. Por eso un envío de 28 bytes es esperado **si ocurre en el socket de
juego 127.0.0.1:5816**. El contenido ya está protegido por el canal de juego y
el hook no intenta descifrarlo; el log lo denomina candidato hasta que el peer y
el servidor confirmen tipo 1052.

Si los 28 bytes aparecen en el socket de login 9958, no deben considerarse
`MsgConnect`: Redux login sólo despacha el tipo 1051 en el código auditado.

## Crash en MSVCRT

El camino 5065 ya no resuelve ni instala un Detour sobre `_snprintf`/`snprintf`.
Ese hook global varargs podía interceptar llamadas no relacionadas, reentrar en
otra función de formato o romper la disciplina cdecl de la pila. Sólo quedan
Detours con ABI `__stdcall` compatible para `connect` y `send`.

Los diagnósticos registran profundidad por hilo y ESP antes y después del
trampoline. Ante `0xC0000005`, registran además una cadena EBP y candidatos
ejecutables encontrados desde ESP. Esto permite distinguir recursión
(`depth > 1`), calling convention incorrecta (`calling-convention-balanced=NO`)
y una cadena EBP no monótona, además de obtener módulos y offsets de la traza.
La eliminación del riesgo está validada por código y pruebas; la
resolución del crash requiere todavía una ejecución con el cliente real.

## Evidencia del Build 57

En Windows 11 x86, el RVA `MSVCRT.dll+0x8DC4A` cae dentro del export
`memcpy` (`memcpy+0x5A`) de `msvcrt.dll` 7.0.26100.9711. Esto demuestra que la
infracción ocurre durante una copia de memoria del cliente, no dentro del
trampoline `send`. Sin el `Conquer.exe` exacto no es posible desensamblar de
forma responsable los callers `0x004BB9D8`, `0x004BA0BC` y `0x0046A7D8`.

El diagnóstico registra ahora el export más cercano y una ventana de código
alrededor de los primeros return addresses. También mantiene un duplicado del
estado del cifrado de login y descifra **sólo una copia privada** de cada envío
para registrar exclusivamente longitud declarada y tipo. Nunca registra los
campos de cuenta, contraseña, servidor ni MAC, y el buffer transmitido sigue
intacto.

## Selector de reinos del SWF original

El login Flash 5065 conserva la lista visual de reinos oficiales (por ejemplo
Dark, Light y Fire). Eso no implica que el cliente esté conectando a esos
servidores: el hook verifica con `getpeername` que cualquier conexión de login
del rango legado termine realmente en Redux. El nombre seleccionado continúa
viajando dentro del paquete 1051 original, pero Redux autentica la cuenta sin
usar ese nombre como destino de red.

La captura del Build 57 confirma que el cliente usa este flujo multirreino. No
se reemplaza ni se modifica el SWF. El tipo del segundo paquete no se dedujo
por su longitud: fue confirmado posteriormente por el observador del Build 59.

## Evidencia del Build 59

El observador confirmó que el segundo envío es `28:1052` (`MsgConnect`), no
1100. En el instante del envío, `getpeername` todavía devuelve
`127.0.0.1:9958`: el mensaje de entrada al juego está saliendo por la conexión
de cuentas en vez de una conexión nueva a `:5816`.

El `Conquer.exe` exacto, SHA-256
`97CCC3276D46D46BB91AD62E758D1FB622C036F6224EED5EA7C121A80E550A89`, estuvo
disponible para desensamblado. `0x004BB9D8` es el retorno de un `memcpy` dentro
del lector de paquetes de la clase de red: copia desde su buffer circular de
64 KiB al buffer local del despachador `0x004BA05D`, llamado desde
`0x0046A7D3`. Por lo tanto, la infracción es una copia de recepción; no es el
trampoline de `send` ni una llamada recursiva a CRT.

El siguiente diagnóstico observa también `recv` sin modificarlo. Descifra una
copia con el contador independiente servidor→cliente y registra exclusivamente
el encabezado 1055, su resultado y el endpoint IP:puerto recibido; el token y
las credenciales se omiten. La traza de excepción agrega registros, dirección
exacta de lectura/escritura y los tres posibles argumentos cdecl de `memcpy`.
