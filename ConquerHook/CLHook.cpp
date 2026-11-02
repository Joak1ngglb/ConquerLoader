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

char tqFormat[] = { 0x25, 0x73, (char)0xA3, (char)0xAC, (char)0xA1, (char)0xA3,
    0x66, 0x64, 0x6A, 0x66, 0x2C, 0x6A, 0x6B, 0x67, 0x66, 0x6B, 0x6C, 0x00 };
char szPassword[32];
char szConfig[MAX_PATH];
HOOK_STUB snprintf_stub, send_stub, connect_stub, shellexec_stub;
typedef int (__stdcall *ConnectProc)(SOCKET,sockaddr_in*,int);
typedef int (__stdcall *SendProc)(SOCKET,PBYTE,int,int);
ConnectProc native5065_connect = NULL;
SendProc native5065_send = NULL;
SOCKET g_loginSocket = INVALID_SOCKET;
SOCKET g_gameSocket = INVALID_SOCKET;
sockaddr_in g_expectedLogin = {};
sockaddr_in g_expectedGame = {};
__declspec(thread) LONG g_sendHookDepth = 0;
PBYTE handler_stub;
CLegacyCipher* legacy;
int ClientVersion = 0, EnableHostName = 0, UpdatedIPS = 0, DisableAutoFixFlash = 0;
BYTE patternDynamic = 0x4F;
char HostName[32] = "";
LPCSTR HeaderConfig = "CLHook";
// Redux/Packets/Login/[1086]Account.cs consumes exactly this 52-byte
// AccountEx layout after the server decrypts the transport stream. The hook
// intentionally does not inspect these credential fields.
struct ReduxAccountLayout5065 {
	enum { Size=52, AccountOffset=4, PasswordRc5Offset=20, ServerOffset=36, FieldSize=16 };
};
struct ReduxGameConnect5065 { enum { Size=28, Type=1052 }; };
static_assert(ReduxAccountLayout5065::ServerOffset + ReduxAccountLayout5065::FieldSize ==
	ReduxAccountLayout5065::Size, "Redux AccountEx layout must remain 52 bytes");
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
static void Flash5065Trace(const char* message);


static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

int csv3_snprintf(char* str, int len, const char* format, ...)
{
	if (!str || len <= 0 || !format) return -1;
	va_list args;
	va_start(args, format);
	int result = -1;
	if (strcmp(format, tqFormat) == 0)
	{
		char* password = va_arg(args, PCHAR);
		if (!password) password = "";
		strcpy_s(szPassword, sizeof(szPassword), password);
		char capture[128]={};
		sprintf_s(capture,"Authentication password captured by CRT hook (length=%u, value redacted).",
			static_cast<unsigned>(strnlen_s(szPassword,sizeof(szPassword))));
		Flash5065Trace(capture);
		if (strcpy_s(str, len, password) != 0 || strcat_s(str, len, &tqFormat[2]) != 0)
			result = -1;
		else
			result = static_cast<int>(strlen(str));

		//MessageBoxA(NULL, szPassword, "Password", MB_OK);

	}
	else
	{
		result = vsnprintf(str, len, format, args);
	}
	va_end(args);
	return result;
}
int __stdcall csv3_connect(SOCKET s, sockaddr_in* name, int len)
{
	char szIPAddress[32], szPortAddress[32];
	int rPort;
	typedef int (__stdcall *LPFCONNECT)(SOCKET,sockaddr_in*,int);
	LPFCONNECT original = native5065_connect ? native5065_connect :
		reinterpret_cast<LPFCONNECT>(connect_stub.Address);
	if(!original || !name || len < static_cast<int>(sizeof(sockaddr_in)) ||
	   name->sin_family != AF_INET) {
		Flash5065Trace("ERROR: connect hook received invalid target/original trampoline.");
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}
	char originalIp[32]={};
	strcpy_s(originalIp,inet_ntoa(name->sin_addr));
	int originalPort=ntohs(name->sin_port);
	bool redirected=false;
	const char* route="passthrough";

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

	rPort = originalPort;
	if (rPort >= 9950 && rPort <= 9970)
	{
		/* START - NO Encrypted Connection */
		GetPrivateProfileStringA(HeaderConfig, "HOST", "", szIPAddress, 32, szConfig);
		GetPrivateProfileStringA(HeaderConfig, "PORT", "9958", szPortAddress, 32, szConfig);
		DWORD configuredAddress=inet_addr(szIPAddress);
		int nPortDecrypt = atoi(szPortAddress);
		if(configuredAddress==INADDR_NONE || nPortDecrypt<1 || nPortDecrypt>65535) {
			Flash5065Trace("ERROR: invalid Redux login HOST/PORT in CLHook.ini.");
			WSASetLastError(WSAEINVAL); return SOCKET_ERROR;
		}
		name->sin_addr.s_addr = configuredAddress;
		name->sin_port = htons(nPortDecrypt);
		redirected=true; route="login";
		g_loginSocket=s; g_expectedLogin=*name;
		// The 5065 client already builds the AccountEx packet and applies both
		// RC5 password protection and the auth transport cipher. Mutating it here
		// corrupts its wire format. Keep the old adapter only for older profiles.
		if(ClientVersion!=5065) {
			if(legacy){delete legacy;legacy=NULL;}
			legacy = new CLegacyCipher();
			legacy->GenerateIV(0x13FA0F9D, 0x6D5C7962);
		}
	}
	else if (rPort == 5816)
	{
		/*	NO Encrypted Connection	*/
		GetPrivateProfileStringA(HeaderConfig, "GAMEHOST", "", szIPAddress, 32, szConfig);
		GetPrivateProfileStringA(HeaderConfig, "GAMEPORT", "5816", szPortAddress,32, szConfig);
		DWORD configuredAddress=inet_addr(szIPAddress);
		int nPortDecrypt = atoi(szPortAddress);
		if(configuredAddress==INADDR_NONE || nPortDecrypt<1 || nPortDecrypt>65535) {
			Flash5065Trace("ERROR: invalid Redux game GAMEHOST/GAMEPORT in CLHook.ini.");
			WSASetLastError(WSAEINVAL); return SOCKET_ERROR;
		}
		name->sin_addr.s_addr = configuredAddress;
		name->sin_port = htons(nPortDecrypt);
		redirected=true; route="game";
		g_gameSocket=s; g_expectedGame=*name;
	}

	//Servername Changer By DaRkFox
	char buffer[16];
	if (ServerNameMemoryAddress != 0) {
		//Input Servername
		WriteProcessMemory(GetCurrentProcess(), (void*)ServerNameMemoryAddress, ServerName, sizeof(buffer), 0);
	}
	//END Servername Changer

	char targetIp[32]={}; strcpy_s(targetIp,inet_ntoa(name->sin_addr));
	char redirectLog[256]={};
	sprintf_s(redirectLog,"connect route=%s redirected=%s original=%s:%d target=%s:%d socket=%llu.",
		route,redirected?"yes":"no",originalIp,originalPort,targetIp,ntohs(name->sin_port),
		static_cast<unsigned long long>(s));
	Flash5065Trace(redirectLog);
	int result=original(s,name,len);
	int error=result==SOCKET_ERROR?WSAGetLastError():0;
	sockaddr_in peer={}; int peerLength=sizeof(peer);
	if(result==0 && getpeername(s,reinterpret_cast<sockaddr*>(&peer),&peerLength)==0) {
		char peerIp[32]={}; strcpy_s(peerIp,inet_ntoa(peer.sin_addr));
		bool verified=peer.sin_addr.s_addr==name->sin_addr.s_addr && peer.sin_port==name->sin_port;
		sprintf_s(redirectLog,"connect completed peer=%s:%d expected=%s:%d verified=%s.",
			peerIp,ntohs(peer.sin_port),targetIp,ntohs(name->sin_port),verified?"yes":"NO");
		Flash5065Trace(redirectLog);
	} else {
		sprintf_s(redirectLog,"connect result=%d WSAError=%d (destination not yet peer-verified).",result,error);
		Flash5065Trace(redirectLog);
	}
	if(result==SOCKET_ERROR)WSASetLastError(error);
	return result;
}
int __stdcall csv3_send(SOCKET s, PBYTE buf, int len, int flags)
{
	LONG depth=++g_sendHookDepth;
	if(ClientVersion==5065)
	{
		char wireLog[320]={};
		sockaddr_in peer={}; int peerLength=sizeof(peer);
		bool peerRead=getpeername(s,reinterpret_cast<sockaddr*>(&peer),&peerLength)==0;
		const char* route="other"; const sockaddr_in* expected=NULL;
		if(s==g_loginSocket){route="login";expected=&g_expectedLogin;}
		else if(s==g_gameSocket){route="game";expected=&g_expectedGame;}
		bool verified=peerRead && expected && peer.sin_addr.s_addr==expected->sin_addr.s_addr &&
			peer.sin_port==expected->sin_port;
		char peerIp[32]="unavailable"; int peerPort=0;
		if(peerRead){strcpy_s(peerIp,inet_ntoa(peer.sin_addr));peerPort=ntohs(peer.sin_port);}
		sprintf_s(wireLog,"send entry route=%s peer=%s:%d verified=%s length=%d depth=%ld; payload is read-only.",
			route,peerIp,peerPort,verified?"yes":"NO",len,depth);
		Flash5065Trace(wireLog);
		if(s==g_loginSocket && len==ReduxAccountLayout5065::Size)
			Flash5065Trace("Redux AccountEx candidate: 52-byte encrypted payload forwarded byte-for-byte; account@4, RC5 password@20 and server@36 were not read or modified.");
		else if(s==g_gameSocket && len==ReduxGameConnect5065::Size)
			Flash5065Trace("Redux MsgConnect(1052) candidate: 28-byte game payload forwarded byte-for-byte; type confirmation remains server-side because the game stream is encrypted.");
		else if(s==g_loginSocket || s==g_gameSocket)
			Flash5065Trace("Protocol send length does not match the expected 52-byte login or 28-byte game candidate for this route; forwarded unchanged.");
	}
	else if (legacy && s == g_loginSocket)
	{
		char authLog[256]={};
		sockaddr_in peer={}; int peerLength=sizeof(peer);
		bool peerRead=getpeername(s,reinterpret_cast<sockaddr*>(&peer),&peerLength)==0;
		bool peerVerified=peerRead && s==g_loginSocket &&
			peer.sin_addr.s_addr==g_expectedLogin.sin_addr.s_addr && peer.sin_port==g_expectedLogin.sin_port;
		if(peerRead) {
			char peerIp[32]={}; strcpy_s(peerIp,inet_ntoa(peer.sin_addr));
			sprintf_s(authLog,"Authentication send peer=%s:%d Redux-target-verified=%s packetLength=%d.",
				peerIp,ntohs(peer.sin_port),peerVerified?"yes":"NO",len);
		} else sprintf_s(authLog,"Authentication send peer unavailable WSAError=%d packetLength=%d.",WSAGetLastError(),len);
		Flash5065Trace(authLog);
		legacy->Decrypt(buf, len);
		const size_t fieldOffset = 4 + 4 + 64;
		const size_t passwordLength = strnlen_s(szPassword, sizeof(szPassword));
		bool passwordPatched=false;
		if (buf && len > static_cast<int>(fieldOffset) && passwordLength>0) {
			size_t available = static_cast<size_t>(len) - fieldOffset;
			size_t used = strnlen_s(reinterpret_cast<char*>(buf + fieldOffset), available);
			if (used < available && passwordLength < available - used)
				{memcpy(buf + fieldOffset + used, szPassword, passwordLength + 1);passwordPatched=true;}
			else
				Flash5065Trace("ERROR: password field did not fit in legacy login packet.");
		}
		else Flash5065Trace("ERROR: authentication password was not captured before send.");

		legacy->Encrypt(buf, len);
		sprintf_s(authLog,"Authentication packet legacy decrypt/patch/encrypt complete; passwordPatched=%s passwordLength=%u.",
			passwordPatched?"yes":"NO",static_cast<unsigned>(passwordLength));
		Flash5065Trace(authLog);
		delete legacy;
		legacy = NULL;
	}
	else if(legacy)
	{
		Flash5065Trace("send observed on a non-login socket; legacy authentication packet left untouched.");
	}

	// invoke old method
	typedef int (__stdcall *LPFSEND)(SOCKET,PBYTE,int,int);
	LPFSEND original = native5065_send ? native5065_send :
		reinterpret_cast<LPFSEND>(send_stub.Address);
	if(!original){Flash5065Trace("ERROR: send trampoline is NULL.");WSASetLastError(WSAEINVAL);--g_sendHookDepth;return SOCKET_ERROR;}
	DWORD stackPointerBefore=0;
	__asm mov stackPointerBefore, esp
	int result=original(s,buf,len,flags);
	DWORD stackPointerAfter=0;
	__asm mov stackPointerAfter, esp
	int error=result==SOCKET_ERROR?WSAGetLastError():0;
	char sendLog[224]={}; sprintf_s(sendLog,"send result=%d requested=%d WSAError=%d depth=%ld ESP-before=0x%08lX ESP-after=0x%08lX calling-convention-balanced=%s.",
		result,len,error,depth,stackPointerBefore,stackPointerAfter,
		stackPointerBefore==stackPointerAfter?"yes":"NO");
	Flash5065Trace(sendLog);
	--g_sendHookDepth;
	if(result==SOCKET_ERROR)WSASetLastError(error);
	return result;
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
    HANDLE file=CreateFileA(filename,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return;
    // Avoid the CRT here: this logger is also used while diagnosing faults
    // whose instruction pointer is inside MSVCRT.
    char line[1024]={};
    int length=wsprintfA(line,"%lu [tid=%lu] [hook] %s\r\n",GetTickCount(),
        GetCurrentThreadId(),message ? message : "(null)");
    DWORD written=0;
    if(length>0)WriteFile(file,line,static_cast<DWORD>(length),&written,NULL);
    CloseHandle(file);
}

static volatile LONG g_exceptionCount=0;
static PVOID g_exceptionHandler=NULL;
static HANDLE g_protocolReadyEvent=NULL;
static HANDLE g_protocolFailedEvent=NULL;
static bool ReadDword5065(DWORD address,DWORD& value) {
    MEMORY_BASIC_INFORMATION memory={};
    if(!address || !VirtualQuery(reinterpret_cast<LPCVOID>(address),&memory,sizeof(memory)) ||
       memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
    DWORD_PTR end=reinterpret_cast<DWORD_PTR>(memory.BaseAddress)+memory.RegionSize;
    if(static_cast<DWORD_PTR>(address)+sizeof(DWORD)>end)return false;
    __try { value=*reinterpret_cast<DWORD*>(address); return true; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
static bool ExecutableAddress5065(DWORD address) {
    MEMORY_BASIC_INFORMATION memory={};
    if(!address || !VirtualQuery(reinterpret_cast<LPCVOID>(address),&memory,sizeof(memory)) ||
       memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
    DWORD protection=memory.Protect&0xff;
    return protection==PAGE_EXECUTE || protection==PAGE_EXECUTE_READ ||
        protection==PAGE_EXECUTE_READWRITE || protection==PAGE_EXECUTE_WRITECOPY;
}
static void LogCodeAddress5065(const char* kind,unsigned index,DWORD address) {
    MEMORY_BASIC_INFORMATION memory={}; char module[MAX_PATH]="unknown"; DWORD offset=0;
    if(VirtualQuery(reinterpret_cast<LPCVOID>(address),&memory,sizeof(memory)) && memory.AllocationBase) {
        GetModuleFileNameA(reinterpret_cast<HMODULE>(memory.AllocationBase),module,MAX_PATH);
        offset=address-static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(memory.AllocationBase));
    }
    char line[640]={};
    wsprintfA(line,"crash-stack %s[%u]=0x%08lX module=%s+0x%08lX.",kind,index,address,module,offset);
    Flash5065Trace(line);
}
static void LogExceptionStack5065(const CONTEXT* context) {
    if(!context)return;
    LogCodeAddress5065("eip",0,context->Eip);
    DWORD frame=context->Ebp;
    for(unsigned index=0;index<12;index++) {
        DWORD next=0,returnAddress=0;
        if(frame<context->Esp || frame-context->Esp>0x100000 || (frame&3) ||
           !ReadDword5065(frame,next) || !ReadDword5065(frame+4,returnAddress)) {
            char state[160]={}; wsprintfA(state,"crash-stack EBP chain stopped at frame=0x%08lX index=%u (invalid/unreadable).",frame,index);
            Flash5065Trace(state); break;
        }
        LogCodeAddress5065("ebp-return",index,returnAddress);
        if(next<=frame || next-frame>0x100000) {
            char state[160]={}; wsprintfA(state,"crash-stack EBP chain corrupt/non-monotonic current=0x%08lX next=0x%08lX.",frame,next);
            Flash5065Trace(state); break;
        }
        frame=next;
    }
    unsigned found=0;
    for(unsigned slot=0;slot<64 && found<12;slot++) {
        DWORD candidate=0;
        if(ReadDword5065(context->Esp+slot*sizeof(DWORD),candidate) && ExecutableAddress5065(candidate))
            LogCodeAddress5065("esp-code",found++,candidate);
    }
}
static void PublishProtocolOutcome(bool ready) {
    wchar_t name[96]={};
    swprintf_s(name,L"Local\\ConquerLoader-Protocol5065-%s-%lu",
        ready?L"Ready":L"Failed",GetCurrentProcessId());
    HANDLE& eventHandle=ready?g_protocolReadyEvent:g_protocolFailedEvent;
    if(!eventHandle)eventHandle=CreateEventW(NULL,TRUE,FALSE,name);
    if(eventHandle)SetEvent(eventHandle);
    Flash5065Trace(ready ? "Protocol hook readiness event published; actual connection/authentication still pending runtime verification." :
        "Protocol hook failure event published.");
}
static LONG CALLBACK Flash5065ExceptionTrace(PEXCEPTION_POINTERS pointers) {
    if(!pointers || !pointers->ExceptionRecord || !pointers->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    DWORD code=pointers->ExceptionRecord->ExceptionCode;
    if(code!=EXCEPTION_ACCESS_VIOLATION && code!=EXCEPTION_ILLEGAL_INSTRUCTION &&
       code!=EXCEPTION_STACK_OVERFLOW)return EXCEPTION_CONTINUE_SEARCH;
    LONG count=InterlockedIncrement(&g_exceptionCount);
    if(count<=12) {
        void* address=pointers->ExceptionRecord->ExceptionAddress;
        MEMORY_BASIC_INFORMATION memory={}; char module[MAX_PATH]="unknown";
        if(VirtualQuery(address,&memory,sizeof(memory)) && memory.AllocationBase)
            GetModuleFileNameA(reinterpret_cast<HMODULE>(memory.AllocationBase),module,MAX_PATH);
        char state[640]={};
        wsprintfA(state,"EXCEPTION code=0x%08lX address=0x%08lX EIP=0x%08lX ESP=0x%08lX EBP=0x%08lX module=%s flash-stage=%s",
            code,static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(address)),pointers->ContextRecord->Eip,pointers->ContextRecord->Esp,
            pointers->ContextRecord->Ebp,module,CFlashFix::StageName());
        Flash5065Trace(state);
        LogExceptionStack5065(pointers->ContextRecord);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void Install5065ExceptionDiagnostics() {
    if(!g_exceptionHandler) {
        g_exceptionHandler=AddVectoredExceptionHandler(1,Flash5065ExceptionTrace);
        Flash5065Trace(g_exceptionHandler ? "Vectored crash diagnostics installed." :
            "ERROR: vectored crash diagnostics could not be installed.");
    }
}

static DWORD WINAPI Flash5065Preflight(LPVOID) {
    Flash5065Trace("Flash preflight worker running outside loader lock.");
    HRESULT hr=CFlashFix::PreflightLocalControl();
    char state[128]={};
    sprintf_s(state,"Flash preflight finished with HRESULT=0x%08lX.",
        static_cast<unsigned long>(hr));
    Flash5065Trace(state);
    return SUCCEEDED(hr)?0:1;
}

// The original 5065 client already builds Redux's 52-byte AccountEx packet.
// Only redirect and observe Winsock. In particular, never detour a process-wide
// varargs CRT function: doing so risks recursion and cdecl stack corruption.
struct ImportedFunction5065 {
    PVOID address;
    char module[64];
    bool exactImport;
    ImportedFunction5065():address(NULL),exactImport(false){module[0]=0;}
};

static bool ExecutableTarget(PVOID address) {
    if(!address)return false;
    MEMORY_BASIC_INFORMATION memory={};
    if(!VirtualQuery(address,&memory,sizeof(memory)) || memory.State!=MEM_COMMIT ||
       (memory.Protect&(PAGE_GUARD|PAGE_NOACCESS)))return false;
    DWORD protection=memory.Protect&0xff;
    return protection==PAGE_EXECUTE || protection==PAGE_EXECUTE_READ ||
        protection==PAGE_EXECUTE_READWRITE || protection==PAGE_EXECUTE_WRITECOPY;
}

static bool MainImportDirectory(BYTE*& image,DWORD& imageSize,
    PIMAGE_IMPORT_DESCRIPTOR& descriptors) {
    image=reinterpret_cast<BYTE*>(GetModuleHandleA(NULL));
    if(!image)return false;
    PIMAGE_DOS_HEADER dos=reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<=0 || dos->e_lfanew>4096)return false;
    PIMAGE_NT_HEADERS32 nt=reinterpret_cast<PIMAGE_NT_HEADERS32>(image+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386)return false;
    imageSize=nt->OptionalHeader.SizeOfImage;
    IMAGE_DATA_DIRECTORY imports=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!imports.VirtualAddress || imports.VirtualAddress>=imageSize)return false;
    descriptors=reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image+imports.VirtualAddress);
    return true;
}

static void LogMainImportModules() {
    BYTE* image=NULL; DWORD imageSize=0; PIMAGE_IMPORT_DESCRIPTOR imports=NULL;
    if(!MainImportDirectory(image,imageSize,imports)) {
        Flash5065Trace("ERROR: Conquer.exe PE import directory is unavailable."); return;
    }
    Flash5065Trace("Conquer.exe PE import inventory follows:");
    for(unsigned i=0;i<256 && imports[i].Name;i++) {
        if(imports[i].Name>=imageSize)break;
        const char* name=reinterpret_cast<const char*>(image+imports[i].Name);
        char line[160]={}; sprintf_s(line,"PE import module[%u]=%s.",i,name);
        Flash5065Trace(line);
    }
}

static ImportedFunction5065 ResolveMainImport(const char* functionName) {
    ImportedFunction5065 result;
    BYTE* image=NULL; DWORD imageSize=0; PIMAGE_IMPORT_DESCRIPTOR imports=NULL;
    if(!MainImportDirectory(image,imageSize,imports))return result;
    for(unsigned descriptorIndex=0;descriptorIndex<256 && imports[descriptorIndex].Name;descriptorIndex++) {
        PIMAGE_IMPORT_DESCRIPTOR descriptor=&imports[descriptorIndex];
        if(descriptor->Name>=imageSize || !descriptor->FirstThunk)continue;
        const char* moduleName=reinterpret_cast<const char*>(image+descriptor->Name);
        PIMAGE_THUNK_DATA32 iat=reinterpret_cast<PIMAGE_THUNK_DATA32>(image+descriptor->FirstThunk);
        PIMAGE_THUNK_DATA32 names=descriptor->OriginalFirstThunk
            ? reinterpret_cast<PIMAGE_THUNK_DATA32>(image+descriptor->OriginalFirstThunk) : NULL;
        if(!names)continue;
        for(unsigned index=0;index<4096 && names[index].u1.AddressOfData;index++) {
            DWORD nameRva=names[index].u1.AddressOfData;
            if(IMAGE_SNAP_BY_ORDINAL32(nameRva) || nameRva>=imageSize)continue;
            PIMAGE_IMPORT_BY_NAME imported=reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image+nameRva);
            if(strcmp(reinterpret_cast<const char*>(imported->Name),functionName)!=0)continue;
            strcpy_s(result.module,moduleName);
            result.exactImport=true;
            PVOID iatTarget=reinterpret_cast<PVOID>(iat[index].u1.Function);
            if(ExecutableTarget(iatTarget))result.address=iatTarget;
            if(!result.address) {
                HMODULE module=GetModuleHandleA(moduleName);
                if(module)result.address=GetProcAddress(module,functionName);
            }
            return result;
        }
    }
    // Some clients resolve a CRT/Winsock export dynamically. Restrict the
    // fallback to modules that Conquer.exe itself imports; never guess a CRT.
    for(unsigned descriptorIndex=0;descriptorIndex<256 && imports[descriptorIndex].Name;descriptorIndex++) {
        if(imports[descriptorIndex].Name>=imageSize)continue;
        const char* moduleName=reinterpret_cast<const char*>(image+imports[descriptorIndex].Name);
        HMODULE module=GetModuleHandleA(moduleName);
        PVOID address=module?GetProcAddress(module,functionName):NULL;
        if(address && ExecutableTarget(address)) {
            strcpy_s(result.module,moduleName); result.address=address;
            return result;
        }
    }
    return result;
}

static void LogResolvedFunction(const char* functionName,const ImportedFunction5065& target) {
    char line[240]={};
    sprintf_s(line,"Protocol resolve function=%s module=%s address=0x%p exact-main-import=%s.",
        functionName,target.module[0]?target.module:"not-found",target.address,
        target.exactImport?"yes":"no");
    Flash5065Trace(line);
}

static DWORD WINAPI Deferred5065ProtocolHooks(LPVOID)
{
    Flash5065Trace("Redux 5065 protocol hook worker started.");
    LogMainImportModules();
    for (int attempt = 0; attempt < 300; ++attempt) {
        ImportedFunction5065 connectTarget=ResolveMainImport("connect");
        ImportedFunction5065 sendTarget=ResolveMainImport("send");
        if(attempt==0 || attempt%20==0) {
            LogResolvedFunction("connect",connectTarget);
            LogResolvedFunction("send",sendTarget);
        }
        if (connectTarget.address && sendTarget.address) {
            native5065_connect = reinterpret_cast<ConnectProc>(connectTarget.address);
            native5065_send = reinterpret_cast<SendProc>(sendTarget.address);
            LONG transaction=DetourTransactionBegin();
            LONG update=transaction==NO_ERROR?DetourUpdateThread(GetCurrentThread()):transaction;
            LONG a=update==NO_ERROR?DetourAttach(reinterpret_cast<PVOID*>(&native5065_connect),csv3_connect):update;
            LONG b=a==NO_ERROR?DetourAttach(reinterpret_cast<PVOID*>(&native5065_send),csv3_send):a;
            char hookLog[256]={};
            sprintf_s(hookLog,"Detour statuses transaction=%ld updateThread=%ld connect=%ld send=%ld; CRT detour=disabled.",
                transaction,update,a,b);
            Flash5065Trace(hookLog);
            bool allAttached=transaction==NO_ERROR && update==NO_ERROR &&
                a==NO_ERROR && b==NO_ERROR;
            LONG committed = allAttached ? DetourTransactionCommit() : DetourTransactionAbort();
            sprintf_s(hookLog,"Protocol DetourTransaction action=%s result=%ld.",
                allAttached?"commit":"abort",committed);
            Flash5065Trace(hookLog);
            if (allAttached && committed == NO_ERROR) {
                Flash5065Trace("Redux connect/send hooks installed; global CRT detour is disabled and authentication payloads are pass-through.");
                PublishProtocolOutcome(true);
                return 0;
            }
            native5065_connect = NULL;
            native5065_send = NULL;
            Flash5065Trace("ERROR: Detours rejected Redux protocol hooks.");
            PublishProtocolOutcome(false);
            return 1;
        }
        Sleep(50);
    }
    Flash5065Trace("ERROR: connect or send import from Conquer.exe remained unresolved after 15 seconds.");
    PublishProtocolOutcome(false);
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
	strcat_s(szConfig, MAX_PATH, "CLHook.ini");

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
        Install5065ExceptionDiagnostics();
        if (!EnableFlashless5065(hModule)) {
            MessageBoxA(NULL, "El cliente no coincide con Conquer.exe 5065 compatible. No se modifico el juego.",
                "Redux - login sin Flash", MB_OK | MB_ICONERROR);
			return;
        }
		HANDLE worker = CreateThread(NULL, 0, Deferred5065ProtocolHooks, NULL, 0, NULL);
		if (worker) CloseHandle(worker);
		else Flash5065Trace("ERROR: native protocol worker could not be created.");
		return;
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
        Install5065ExceptionDiagnostics();
        char state[96] = {};
        sprintf_s(state, "Early 5065 hook entry. Diagnostic mode=%d.", diagnosticMode);
        Flash5065Trace(state);
    }

    if (!flashless && ClientVersion <= 6186 && !DisableAutoFixFlash) {
        if (!earlyFlash5065 || diagnosticMode < 3) {
            if (earlyFlash5065) Flash5065Trace("Installing Flash detour...");
            HRESULT flashHook=CFlashFix::Hook(!earlyFlash5065 || diagnosticMode < 2);
            bool versionGateReady=!earlyFlash5065 || EnableLocalFlashCompatibility5065();
            char flashState[128]={};
            sprintf_s(flashState,"Flash detour installation returned HRESULT=0x%08lX.",
                static_cast<unsigned long>(flashHook));
            if (earlyFlash5065) Flash5065Trace(flashState);
            if(SUCCEEDED(flashHook) && versionGateReady) {
                HANDLE preflight=CreateThread(NULL,0,Flash5065Preflight,NULL,0,NULL);
                if(preflight)CloseHandle(preflight);
                else Flash5065Trace("ERROR: failed to start Flash preflight thread.");
            } else if(earlyFlash5065) {
                Flash5065Trace("ERROR: Flash hook or exact-build version compatibility failed.");
                CFlashFix::PublishStartupFailure();
            }
        } else Flash5065Trace("All Flash hooks disabled for isolation.");
    }

    // Dragon-style pre-entry injection: do not install 5065 network hooks
    // unless mode 0 was explicitly selected after the Flash-only test.
    if (earlyFlash5065) {
        if (diagnosticMode == 0) {
            Flash5065Trace("Installing network hook on deferred thread.");
            HANDLE worker = CreateThread(NULL, 0, Deferred5065ProtocolHooks, NULL, 0, NULL);
            if (worker) CloseHandle(worker);
            else Flash5065Trace("ERROR: failed to start deferred network hook thread.");
        } else {
            Flash5065Trace("Network hook skipped in diagnostic mode.");
        }
        return;
    }

    // Even if a hand-written configuration omits EARLY_FLASH5065, never send
    // this exact protocol through the legacy global _snprintf hook below.
    if(ClientVersion==5065) {
        Flash5065Trace("5065 fallback: installing Winsock-only protocol hooks; CRT detour remains disabled.");
        HANDLE worker=CreateThread(NULL,0,Deferred5065ProtocolHooks,NULL,0,NULL);
        if(worker)CloseHandle(worker);
        else {Flash5065Trace("ERROR: failed to start 5065 fallback protocol worker.");PublishProtocolOutcome(false);}
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
			strcpy_s(szDebug, "Failed to find correct pattern1");
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
				strcpy_s(szDebug, "Failed to find correct pattern2");
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

void csv3_shutdown()
{
    if(g_exceptionHandler) {
        RemoveVectoredExceptionHandler(g_exceptionHandler);
        g_exceptionHandler=NULL;
    }
    if(g_protocolReadyEvent){CloseHandle(g_protocolReadyEvent);g_protocolReadyEvent=NULL;}
    if(g_protocolFailedEvent){CloseHandle(g_protocolFailedEvent);g_protocolFailedEvent=NULL;}
    g_loginSocket=INVALID_SOCKET; g_gameSocket=INVALID_SOCKET;
    SecureZeroMemory(szPassword,sizeof(szPassword));
}
