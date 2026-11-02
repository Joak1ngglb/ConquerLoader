// CSV3Hook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "hook.h"
#include <iostream>
#include "LegacyCipher.h"
#include <fstream>
#include <sstream>
#include <string>
//Implement GetHostName By IP
#include <iostream>
#include <time.h>
//
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include "CFlashFix.h"
#include "Flashless5065.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

using namespace std;

//
// hooks.h is from a library/project (MID) that I (InfamousNoone) wrote back in 2010.
// It was a /FAILED/ project, and I decided to discontinue it.
// If anyone is interested in it, they can see the following link below:
// http://subversion.assembla.com/svn/mid_project/trunk/MID_LIBRARY/
//

#define lib_func(lib, func) (GetProcAddress(GetModuleHandleA(lib), func))

char tqFormat[] = { 0x25, 0x73, 0xA3, 0xAC, 0xA1, 0xA3, 0x66, 0x64, 0x6A, 0x66, 0x2C, 0x6A, 0x6B, 0x67, 0x66, 0x6B, 0x6C, 0x00 };
char szPassword[32];
char szConfig[MAX_PATH];
HOOK_STUB snprintf_stub, send_stub, connect_stub, shellexec_stub;
PBYTE handler_stub;
CLegacyCipher* legacy;
int ClientVersion = 0, EnableHostName = 0, UpdatedIPS = 0, DisableAutoFixFlash = 0;
BYTE patternDynamic = 0x4F;
char HostName[32] = "";
LPCSTR HeaderConfig = "CLHook";
// Variables of Settings from .ini file
char ServerName[16] = "ConquerOnline";
int ServerNameMemoryAddress = 0x005726DC;
// Patterns for working connection
BYTE pattern_6738[] = { 0x85, 0xC0, 0x75, 0x2F, 0x8B, 0x4F, 0x14, 0xE8, 0x2B, 0xF0, 0xFF, 0xFF, 0x83, 0x4D, 0xFC, 0xFF, 0x8B, 0x4D, 0xF4 }; // Version = 6738+
BYTE pattern_6711[] = { 0x85, 0xC0, 0x75, 0x2F, 0x8B, 0x4F, 0x14, 0xE8, 0x95, 0xF1, 0xFF, 0xFF, 0x83, 0x4D, 0xFC, 0xFF, 0x8B, 0x4D, 0xF4 }; // Version = 6711+
BYTE pattern_6617[] = { 0x85, 0xC0, 0x75, 0x2F, 0x8B, 0x4F, 0x14, 0xE8, 0x0D, 0xF1, 0xFF, 0xFF, 0x83, 0x4D, 0xFC, 0xFF, 0x8B, 0x4D, 0xF4 }; // Version = 6617
BYTE pattern_60XX[] = { 0x85, 0xC0, 0x75, 0x00, 0x8B, 0x4F, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x4D, 0x00, 0x00, 0x8B, 0x00, 0x00 }; // Version = 60XX
BYTE pattern_5600_OR_UPPER[] = { 0x85, 0xC0, 0x75, 0x00, 0x8B, 0x4E, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x4D, 0x00, 0x00, 0x8B, 0x00, 0x00 }; // Version = Old Clients
BYTE pattern_5810_OR_UPPER[] = { 0x85, 0xC0, 0x75, 0x00, 0x8B, 0x4F, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x4D, 0x00, 0x00, 0x8B, 0x00, 0x00 }; // Version = 5810+
BYTE pattern_5700_OR_UPPER[] = { 0x85, 0xC0, 0x74, 0x0E, 0x8B, 0x45, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0xE9, 0xA2, 0x00, 0x00, 0x00, 0x00 }; // Version = 57XX+
BYTE pattern2[] = { 0x85, 0xC9, 0x00, 0x00, 0xFF, 0x75, 0x00, 0x57, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x89, 0x45 }; // All version using this pattern2
BYTE pattern2_6617[] = { 0x85, 0xC9, 0x74, 0x0C, 0xFF, 0x75, 0x0C, 0x57, 0xE8, 0x53, 0xF2, 0xFF, 0xFF, 0x89, 0x45 }; // Pattern2. Version = 6617

extern LPVOID FindMemoryPattern(PBYTE pattern, bool* wildCards, int len);


static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

int csv3_snprintf(char* str, int len, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	if (strcmp(format, tqFormat) == 0)
	{
		char* password = va_arg(args, PCHAR);
		strcpy(szPassword, password);
		str[0] = NULL;
		strcat(str, password);
		strcat(str, &tqFormat[2]);

		//MessageBoxA(NULL, szPassword, "Password", MB_OK);

		return strlen(str);
	}
	else
	{
		return vsnprintf(str, len, format, args);
	}
}
int __stdcall csv3_connect(SOCKET s, sockaddr_in* name, int len)
{
	char szIPAddress[32], szPortAddress[32];
	int rPort;

	//END - Get hostname by ip
	EnableHostName = GetPrivateProfileIntA(HeaderConfig, "ENABLE_HOSTNAME", 0, szConfig);

	if (EnableHostName == 1) {
		//Get hostname by ip
		GetPrivateProfileStringA(HeaderConfig, "HOSTNAME", "", HostName, 32, szConfig);
		if (strlen(HostName)>0 && UpdatedIPS == 0) {
			hostent * record = gethostbyname(HostName);
			if (record == NULL)
			{
				MessageBoxA(NULL, "No se ha podido obtener la IP del HostName!", "Error", MB_OK + MB_ICONERROR);
			}
			else {
				in_addr * address = (in_addr *)record->h_addr;
				if (WritePrivateProfileStringA(HeaderConfig, "HOST", inet_ntoa(*address), szConfig)) {
					if (WritePrivateProfileStringA(HeaderConfig, "GAMEHOST", inet_ntoa(*address), szConfig)) {
						UpdatedIPS = 1;
					}
				}
			}
		}
		//
	}

	rPort = ntohs(name->sin_port);
	if (rPort >= 9950 && rPort <= 9970)
	{
		/* START - NO Encrypted Connection */
		GetPrivateProfileStringA(HeaderConfig, "HOST", "", szIPAddress, 32, szConfig);
		GetPrivateProfileStringA(HeaderConfig, "PORT", "9958", szPortAddress, 32, szConfig);
		name->sin_addr.s_addr = inet_addr(szIPAddress);
		int nPortDecrypt = atoi(szPortAddress);
		name->sin_port = htons(nPortDecrypt);
		legacy = new CLegacyCipher();
		legacy->GenerateIV(0x13FA0F9D, 0x6D5C7962);
	}
	else if (rPort == 5816)
	{
		/*	NO Encrypted Connection	*/
		GetPrivateProfileStringA(HeaderConfig, "GAMEHOST", "", szIPAddress, 32, szConfig);
		GetPrivateProfileStringA(HeaderConfig, "GAMEPORT", "5816", szPortAddress,32, szConfig);
		name->sin_addr.s_addr = inet_addr(szIPAddress);
		int nPortDecrypt = atoi(szPortAddress);
		name->sin_port = htons(nPortDecrypt);
	}

	//Servername Changer By DaRkFox
	char buffer[16];
	if (ServerNameMemoryAddress != 0) {
		//Input Servername
		WriteProcessMemory(GetCurrentProcess(), (void*)ServerNameMemoryAddress, ServerName, sizeof(buffer), 0);
	}
	//END Servername Changer

	typedef int (__stdcall *LPFCONNECT)(SOCKET,sockaddr_in*,int);
	return ((LPFCONNECT)connect_stub.Address)(s, name, len);
}
int __stdcall csv3_send(SOCKET s, PBYTE buf, int len, int flags)
{
	if (legacy)
	{
		legacy->Decrypt(buf, len);

		strcat((char*)&buf[4+4+64], szPassword);

		legacy->Encrypt(buf, len);
		delete legacy;
		legacy = NULL;
	}

	// invoke old method
	typedef int (__stdcall *LPFSEND)(SOCKET,PBYTE,int,int);
	return ((LPFSEND)send_stub.Address)(s,buf,len,flags);
}
int __stdcall csv3_shellexec(HWND hwnd, char* lpOperation, char* lpFile, char* lpParams, char* lpDir, int nCmd)
{
	return SE_ERR_FNF;
}

BOOL __stdcall csv3_handler(PBYTE msg)
{
	return TRUE; // allow TQ to process this packet
}

PBYTE tq_handler;
__declspec(naked) BOOL __stdcall csv3_handler_hook()
{
	__asm
	{
		nop
		push ebp
		mov ebp, esp
		push dword ptr[ebp+12]
		push dword ptr[ebp+8]
		// ecx is already set
		mov eax, tq_handler		// this method cleans up after itself __stdcall
		call eax
		test eax,eax
		jz _leave
		// we have a packet... pass it to csv3_handler
		push dword ptr[ebp+12]
		call csv3_handler
		//
		_leave:
		pop ebp
		ret 8 // clean up after self
	}
}

PBYTE tq_send;
__declspec(naked) DWORD __stdcall csv3_tqsend(PBYTE msg, DWORD len)
{
	__asm
	{
		nop
		mov eax, tq_send
		jmp eax
	}
}

// The pre-entry Flash hook is loaded by an APC before Conquer initializes
// its imports. WS2_32.dll is a static import of the game, but the module may
// not be usable yet when the APC runs. Do NOT dereference a NULL connect
// address: the old CreateHook32 would crash inside memcmp(NULL,...).
static void Flash5065Trace(const char* message)
{
    char filename[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(NULL, filename, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    char* slash = strrchr(filename, '\\');
    if (!slash) return;
    strcpy_s(slash + 1, MAX_PATH - (slash + 1 - filename), "CLHook-5065.log");
    FILE* file = NULL;
    if (fopen_s(&file, filename, "a") == 0 && file) {
        fprintf(file, "%lu %s\n", GetTickCount(), message);
        fclose(file);
    }
}
static DWORD WINAPI Deferred5065ConnectHook(LPVOID)
{
    Flash5065Trace("Deferred network hook started; waiting for ws2_32.dll.");
    for (int attempt = 0; attempt < 300; ++attempt) {
        HMODULE winsock = GetModuleHandleA("ws2_32.dll");
        LPVOID connectAddress = winsock ? GetProcAddress(winsock, "connect") : NULL;
        if (connectAddress) {
            // No other network hooks are installed in 5065 mode.
            // The game starts disconnected, so it is safe to wait for imports.
            CreateHook32(connectAddress, csv3_connect, &connect_stub);
            Flash5065Trace("Deferred connect hook installed successfully.");
            return 0;
        }
        Sleep(50);
    }
    Flash5065Trace("ERROR: ws2_32/connect was not available within 15 seconds.");
    return 1;
}

void csv3_init(HMODULE hModule)
{
	float f = 0; // load support for floating operations -- thx ntl3fty!
	char szDebug[256];

	// Get config from .ini
	GetModuleFileNameA(NULL, szConfig, MAX_PATH);
	for (int i = strlen(szConfig) - 1; i >= 0; i--)
	{
		if (szConfig[i] == '\\')
		{
			szConfig[i + 1] = NULL;
			break;
		}
	}
	strcat(szConfig, "CLHook.ini");

	// Find the correct version of client based in user config
	ClientVersion = GetPrivateProfileIntA(HeaderConfig, "SERVER_VERSION", 0, szConfig);
	DisableAutoFixFlash = GetPrivateProfileIntA(HeaderConfig, "DISABLE_AUTOFIX_FLASH", 0, szConfig);

	// Get the servername
	GetPrivateProfileStringA(HeaderConfig, "SERVERNAME", "ConquerOnline", ServerName, 16, szConfig);
	ServerNameMemoryAddress = GetPrivateProfileIntA(HeaderConfig, "SERVERNAME_MEMORYADDRESS", 0, szConfig);

	// debug client version number
	//std::string s = std::to_string(ClientVersion);
	//MessageBoxA(NULL, s.c_str(), "INFO TEST", MB_OK);

	// Flash-less mode uses Win32 credential fields + original client network auth.
    // Only attempt against the exact Conquer.exe build given by the user.
    bool flashless = ClientVersion == 5065 &&
        GetPrivateProfileIntA(HeaderConfig, "FLASHLESS_NATIVE_LOGIN", 0, szConfig) == 1;
    if (flashless) {
        if (!EnableFlashless5065(hModule)) {
            MessageBoxA(NULL, "El cliente no coincide con Conquer.exe 5065 compatible. No se modifico el juego.",
                "Redux - login sin Flash", MB_OK | MB_ICONERROR);
        }
    }

    // Stage isolation: distinguish failures originating in Flash/COM detours
    // from the unsafe legacy Winsock patching path. The 5065 diagnostic profile
    // defaults to mode 1; no network hook is installed in diagnostic mode.
    bool earlyFlash5065 = ClientVersion == 5065 && !flashless &&
        GetPrivateProfileIntA(HeaderConfig, "EARLY_FLASH5065", 0, szConfig) == 1;
    int diagnosticMode = earlyFlash5065
        ? GetPrivateProfileIntA(HeaderConfig, "FLASH5065_DIAGNOSTIC_MODE", 1, szConfig)
        : 0;
    if (diagnosticMode < 0 || diagnosticMode > 3) diagnosticMode = 1;
    if (earlyFlash5065) {
        char state[96] = {};
        sprintf_s(state, "Early 5065 hook entry. Diagnostic mode=%d.", diagnosticMode);
        Flash5065Trace(state);
    }

    if (!flashless && ClientVersion <= 6186 && !DisableAutoFixFlash) {
        if (!earlyFlash5065 || diagnosticMode < 3) {
            if (earlyFlash5065) Flash5065Trace("Installing Flash detour...");
            CFlashFix flash;
            flash.Hook(!earlyFlash5065 || diagnosticMode < 2);
            if (earlyFlash5065) Flash5065Trace("Flash detour installation returned.");
        } else Flash5065Trace("All Flash hooks disabled for isolation.");
    }

    // Dragon-style pre-entry injection: do not install 5065 network hooks
    // unless mode 0 was explicitly selected after the Flash-only test.
    if (earlyFlash5065) {
        if (diagnosticMode == 0) {
            Flash5065Trace("Installing network hook on deferred thread.");
            HANDLE worker = CreateThread(NULL, 0, Deferred5065ConnectHook, NULL, 0, NULL);
            if (worker) CloseHandle(worker);
            else Flash5065Trace("ERROR: failed to start deferred network hook thread.");
        } else {
            Flash5065Trace("Network hook skipped in diagnostic mode.");
        }
        return;
    }

	if (ClientVersion >= 5600) {
		//
		//	hook packet processor
		//

		bool wildcards[] = { 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1 };
		PBYTE match = (PBYTE)FindMemoryPattern(pattern_5600_OR_UPPER, wildcards, 19);

		if (ClientVersion >= 5700) {
			match = (PBYTE)FindMemoryPattern(pattern_5700_OR_UPPER, wildcards, 19);
		}
		if (ClientVersion >= 5810) {
			match = (PBYTE)FindMemoryPattern(pattern_5810_OR_UPPER, wildcards, 19);
		}
		if (ClientVersion >= 6000) {
			match = (PBYTE)FindMemoryPattern(pattern_60XX, wildcards, 19);
		}
		if (ClientVersion >= 6617) {
			match = (PBYTE)FindMemoryPattern(pattern_6617, wildcards, 19);
		}
		if (ClientVersion >= 6711 && ClientVersion <= 6737) { // 6711 to 6737
			match = (PBYTE)FindMemoryPattern(pattern_6711, wildcards, 19);
		}
		if (ClientVersion >= 6738 && ClientVersion <= 6900) { // 6738 to 6900
			match = (PBYTE)FindMemoryPattern(pattern_6738, wildcards, 19);
		}

		if (match == NULL)
		{
			sprintf(szDebug, "Failed to find correct pattern1", (DWORD)match);
			MessageBoxA(NULL, szDebug, "ERROR", MB_OK);
			return;
		}

		DWORD callDstInter;
		match = match - 5; // where the call occurs
		ReadProcessMemory(GetCurrentProcess(), match + 1, &callDstInter, sizeof(callDstInter), NULL);
		tq_handler = (PBYTE)((DWORD)match - (UINT_MAX - callDstInter) + 4);
		// update the intermediate to our hook
		callDstInter = (DWORD)csv3_handler_hook - (DWORD)match + UINT_MAX - 4;
		WriteProcessMemory(GetCurrentProcess(), match + 1, &callDstInter, sizeof(callDstInter), NULL);

		if (ClientVersion < 6738) {
			bool wildcards2[] = { 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0 };
			match = (PBYTE)FindMemoryPattern(pattern2, wildcards2, 15);

			if (ClientVersion >= 6600) {
				match = (PBYTE)FindMemoryPattern(pattern2_6617, wildcards2, 15);
			}

			if (match == NULL)
			{
				sprintf(szDebug, "Failed to find correct pattern2", (DWORD)match);
				MessageBoxA(NULL, szDebug, "ERROR", MB_OK);
				return;
			}

			match += 8;
			ReadProcessMemory(GetCurrentProcess(), match + 1, &callDstInter, sizeof(callDstInter), NULL);
		}
		tq_send = (PBYTE)((DWORD)match - (UINT_MAX - callDstInter) + 4);

		memset(szPassword, 0, 32);

		CreateHook32(lib_func("msvcr90.dll", "_snprintf"), csv3_snprintf, &snprintf_stub);
		CreateHook32(lib_func("ws2_32.dll", "send"), csv3_send, &send_stub);
	}
	CreateHook32(lib_func("ws2_32.dll", "connect"), csv3_connect, &connect_stub);
}