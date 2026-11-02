#include "stdafx.h"
#include "Flashless5065.h"
#include <windows.h>
#include <wincrypt.h>
#include <cstring>
#include <cstdio>
#pragma comment(lib, "advapi32.lib")

extern char szConfig[MAX_PATH];

// Reverse-engineered for the supplied PE32 dated 2008-08-24 ONLY.
// A mismatch fails closed, without patching arbitrary client versions.
namespace {
const DWORD kTimestamp=0x48b121fe, kSize=0x18f000;
const DWORD kConstructorRva=0x3121e, kFlashCheckRva=0x7a0b1, kNativeLoginRva=0x31e38;
// Reverse-engineered from Conquer.exe 5065:
// 0x468A89 stores the main game object's pointer at 0x56BF4C.
// Its nested DlgLoginFlash object starts at game object + 0xA0.
// The original constructor runs BEFORE the launcher injects CLHook.dll,
// so hooking that constructor later cannot capture the login object.
const DWORD kGameObjectGlobalRva=0x16bf4c, kLoginOffset=0xa0;
const DWORD kLoginVtableRva=0x12d940;
const BYTE kExpectedSha256[32]={
    0x97,0xcc,0xc3,0x27,0x6d,0x46,0xd4,0x6b,0xb9,0x1a,0xd6,0x2e,0x75,0x8d,0x1f,0xb6,
    0x22,0xc0,0x36,0xf6,0x22,0x4e,0xed,0x5e,0xa7,0xc1,0x21,0xa8,0x0e,0x55,0x0a,0x89};
const UINT kSubmit=WM_APP+5065;
HMODULE g_module=NULL;
HHOOK g_hook=NULL;
HWND g_user=NULL, g_pass=NULL, g_status=NULL, g_loginWindow=NULL;
DWORD g_nativeGameThread=0;
BYTE* g_nativeLoginObject=NULL;
HWND g_gameWindow=NULL;
volatile LONG g_windowSizeChecked=0;
char g_account[16]={0}, g_password[16]={0};
volatile LONG g_pending=0;
BYTE* g_image=NULL;
char g_server[32]="Redux";

void Trace(const char* message) {
    char path[MAX_PATH]={};
    DWORD n=GetModuleFileNameA(NULL,path,MAX_PATH);
    if(!n || n>=MAX_PATH)return;
    char* slash=strrchr(path,'\\');
    if(!slash)return;
    strcpy_s(slash+1,MAX_PATH-(slash+1-path),"CLHook-5065.log");
    FILE* file=NULL;
    if(fopen_s(&file,path,"a")==0 && file) {
        SYSTEMTIME now={}; GetLocalTime(&now);
        fprintf(file,"%02u:%02u:%02u.%03u [native] %s\n",now.wHour,now.wMinute,
            now.wSecond,now.wMilliseconds,message);
        fclose(file);
    }
}
bool ExactFileHash() {
    wchar_t path[MAX_PATH]={};
    if(!GetModuleFileNameW(NULL,path,MAX_PATH))return false;
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return false;
    HCRYPTPROV provider=0; HCRYPTHASH hash=0; bool ok=false;
    if(CryptAcquireContextW(&provider,NULL,NULL,PROV_RSA_AES,CRYPT_VERIFYCONTEXT) &&
       CryptCreateHash(provider,CALG_SHA_256,0,0,&hash)) {
        BYTE buffer[64*1024]; DWORD read=0; BOOL readOk=TRUE; ok=true;
        while((readOk=ReadFile(file,buffer,sizeof(buffer),&read,NULL)) && read) {
            if(!CryptHashData(hash,buffer,read,0)){ok=false;break;}
        }
        if(!readOk)ok=false;
        BYTE digest[32]={}; DWORD size=sizeof(digest);
        ok=ok && CryptGetHashParam(hash,HP_HASHVAL,digest,&size,0) && size==sizeof(digest) &&
            memcmp(digest,kExpectedSha256,sizeof(digest))==0;
        SecureZeroMemory(buffer,sizeof(buffer));
    }
    if(hash)CryptDestroyHash(hash);
    if(provider)CryptReleaseContext(provider,0);
    CloseHandle(file);
    return ok;
}
bool RegionAllows(const void* address,size_t bytes,DWORD required) {
    MEMORY_BASIC_INFORMATION region={};
    if(!VirtualQuery(address,&region,sizeof(region)) || region.State!=MEM_COMMIT ||
       (region.Protect&(PAGE_NOACCESS|PAGE_GUARD)))return false;
    const BYTE* start=reinterpret_cast<const BYTE*>(address);
    const BYTE* end=reinterpret_cast<const BYTE*>(region.BaseAddress)+region.RegionSize;
    if(end<start || static_cast<size_t>(end-start)<bytes)return false;
    return required==0 || (region.Protect&required)!=0;
}

bool WriteCode(BYTE* address,const void* data,size_t size) {
    DWORD previous=0, ignored=0;
    if(!RegionAllows(address,size,0) ||
       !VirtualProtect(address,size,PAGE_EXECUTE_READWRITE,&previous))return false;
    memcpy(address,data,size);
    FlushInstructionCache(GetCurrentProcess(),address,size);
    VirtualProtect(address,size,previous,&ignored);
    return true;
}
bool ExactBuild() {
    HMODULE module=GetModuleHandleA(NULL);
    if(!module || !ExactFileHash())return false;
    g_image=reinterpret_cast<BYTE*>(module);
    PIMAGE_DOS_HEADER mz=reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if(mz->e_magic!=IMAGE_DOS_SIGNATURE || mz->e_lfanew<0 || mz->e_lfanew>4096)return false;
    PIMAGE_NT_HEADERS32 nt=reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<BYTE*>(module)+mz->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 ||
       nt->FileHeader.TimeDateStamp!=kTimestamp || nt->OptionalHeader.SizeOfImage!=kSize)return false;
    const BYTE ctor[]={0xb8,0x91,0x9e,0x51,0x00,0xe8,0xf8,0xf0,0x0b,0x00};
    const BYTE check[]={0xb8,0x2d,0xda,0x51,0x00,0xe8,0x65,0x62,0x07,0x00};
    BYTE* constructor=g_image+kConstructorRva;
    BYTE* flashCheck=g_image+kFlashCheckRva;
    BYTE* nativeLogin=g_image+kNativeLoginRva;
    return RegionAllows(constructor,sizeof(ctor),0) && RegionAllows(flashCheck,sizeof(check),0) &&
           RegionAllows(nativeLogin,1,0) &&
           memcmp(constructor,ctor,sizeof(ctor))==0 && memcmp(flashCheck,check,sizeof(check))==0;
}
// Obtain the object that already exists; the constructor was called before DLL injection.
bool Ready() {
    if(!g_image)return false;
    DWORD* global=reinterpret_cast<DWORD*>(g_image+kGameObjectGlobalRva);
    if(!RegionAllows(global,sizeof(*global),0))return false;
    DWORD base=*reinterpret_cast<volatile DWORD*>(global);
    if(base<0x10000 || base>0x7ff00000)return false;
    BYTE* object=reinterpret_cast<BYTE*>(base+kLoginOffset);
    MEMORY_BASIC_INFORMATION region={};
    if(!VirtualQuery(object,&region,sizeof(region)) || region.State!=MEM_COMMIT ||
       (region.Protect&(PAGE_NOACCESS|PAGE_GUARD)))return false;
    BYTE* regionEnd=reinterpret_cast<BYTE*>(region.BaseAddress)+region.RegionSize;
    if(regionEnd<object || static_cast<size_t>(regionEnd-object)<0x3e0)return false;
    if(*reinterpret_cast<volatile DWORD*>(object)!=reinterpret_cast<DWORD>(g_image+kLoginVtableRva))return false;
    g_nativeLoginObject=object;
    return true;
}
// Enumerate only real top-level client windows in the current game process.
// The separate native login popup is NOT the game viewport.
struct GameWindowInfo { HWND hwnd; DWORD thread; LONG width; LONG height; };
BOOL CALLBACK FindGameWindow(HWND hwnd,LPARAM context) {
    GameWindowInfo* info=reinterpret_cast<GameWindowInfo*>(context);
    DWORD processId=0;
    DWORD threadId=GetWindowThreadProcessId(hwnd,&processId);
    if(processId!=GetCurrentProcessId() || hwnd==g_loginWindow || !IsWindowVisible(hwnd))
        return TRUE;
    if(threadId==GetCurrentThreadId() || GetWindow(hwnd,GW_OWNER)!=NULL)return TRUE;
    RECT bounds={};
    if(!GetWindowRect(hwnd,&bounds))return TRUE;
    LONG width=bounds.right-bounds.left;
    LONG height=bounds.bottom-bounds.top;
    // Affected client displays a ~800-pixel wide, thin patterned border.
    // Ignore helper windows, then pick the largest plausible game viewport.
    if(width<450 || width>4096 || height<12 || height>2160)return TRUE;
    if(!info->hwnd || width>info->width) {
        info->hwnd=hwnd; info->thread=threadId;
        info->width=width; info->height=height;
    }
    return TRUE;
}
GameWindowInfo ResolveGameWindow() {
    GameWindowInfo info={};
    EnumWindows(FindGameWindow,reinterpret_cast<LPARAM>(&info));
    return info;
}
bool RecoverCollapsedGameWindow(const GameWindowInfo& game) {
    if(!game.hwnd || game.height>=180 || game.width<450)return false;
    // Keep the existing client width and restore its 4:3 viewport aspect.
    // Some 5065 distributions default to 800x600, others to 1024x768.
    // Use only the measured dimensions of the game's own window.
    LONG style=GetWindowLongA(game.hwnd,GWL_STYLE);
    LONG exStyle=GetWindowLongA(game.hwnd,GWL_EXSTYLE);
    RECT currentClient={};
    if(!GetClientRect(game.hwnd,&currentClient))return false;
    int clientWidth=currentClient.right-currentClient.left;
    if(clientWidth<640 || clientWidth>1600)return false;
    int clientHeight=clientWidth*3/4;
    RECT desired={0,0,clientWidth,clientHeight};
    if(!AdjustWindowRectEx(&desired,static_cast<DWORD>(style),FALSE,
                          static_cast<DWORD>(exStyle)))return false;
    int outerWidth=desired.right-desired.left;
    int outerHeight=desired.bottom-desired.top;
    if(outerWidth<650 || outerHeight<450)return false;
    return SetWindowPos(game.hwnd,NULL,0,0,outerWidth,outerHeight,
        SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_FRAMECHANGED)!=FALSE;
}
LRESULT CALLBACK OnGameMessage(int code,WPARAM w,LPARAM l) {
    if(code>=0 && l) {
        MSG* msg=reinterpret_cast<MSG*>(l);
        if(msg->message==kSubmit && InterlockedExchange(&g_pending,0)) {
            if(Ready()) {
                BYTE* self=reinterpret_cast<BYTE*>(g_nativeLoginObject);
                // From this exact binary: [self+2d8] account, [+358] password.
                // Flash CMD_SELECTGROUP/CMD_SELECTSERVER normally supplies these indices.
                if(*reinterpret_cast<DWORD*>(self+0x2d0)==0xffffffff)
                    *reinterpret_cast<DWORD*>(self+0x2d0)=0;
                if(*reinterpret_cast<DWORD*>(self+0x2d4)==0xffffffff)
                    *reinterpret_cast<DWORD*>(self+0x2d4)=0;
                memset(self+0x2d8,0,128);
                memset(self+0x358,0,128);
                memcpy(self+0x2d8,g_account,strlen(g_account));
                memcpy(self+0x358,g_password,strlen(g_password));
                SecureZeroMemory(g_password,sizeof(g_password));
                typedef void (__thiscall *GameLogin)(void*);
                Trace("Credentials copied; invoking verified 5065 login routine.");
                __try {
                    (reinterpret_cast<GameLogin>(g_image+kNativeLoginRva))(self);
                    Trace("5065 login routine returned normally.");
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    char error[96]={};
                    sprintf_s(error,"ERROR: login routine raised exception 0x%08lX.",GetExceptionCode());
                    Trace(error);
                }
                SecureZeroMemory(g_account,sizeof(g_account));
            }
            msg->message=WM_NULL;
        }
    }
    return CallNextHookEx(g_hook,code,w,l);
}
void Status(const char* s){if(g_status)SetWindowTextA(g_status,s);}
LRESULT CALLBACK UiProc(HWND hwnd,UINT message,WPARAM w,LPARAM l) {
    switch(message) {
        case WM_CREATE: {
            HFONT font=reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            HWND title=CreateWindowA("STATIC","Conquer 5065 - Login nativo sin Flash",
                WS_VISIBLE|WS_CHILD,18,15,330,24,hwnd,NULL,g_module,NULL);
            char selected[96]={}; sprintf_s(selected,"Servidor: %s",g_server);
            HWND serverLabel=CreateWindowA("STATIC",selected,WS_VISIBLE|WS_CHILD,
                18,40,330,20,hwnd,NULL,g_module,NULL);
            HWND accountLabel=CreateWindowA("STATIC","Cuenta:",WS_VISIBLE|WS_CHILD,
                18,72,88,23,hwnd,NULL,g_module,NULL);
            g_user=CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL,
                110,65,235,28,hwnd,reinterpret_cast<HMENU>(101),g_module,NULL);
            HWND passLabel=CreateWindowA("STATIC","Contrasena:",WS_VISIBLE|WS_CHILD,
                18,111,88,23,hwnd,NULL,g_module,NULL);
            g_pass=CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_PASSWORD,
                110,104,235,28,hwnd,reinterpret_cast<HMENU>(102),g_module,NULL);
            HWND button=CreateWindowA("BUTTON","Entrar",WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_DEFPUSHBUTTON,
                110,148,235,32,hwnd,reinterpret_cast<HMENU>(103),g_module,NULL);
            g_status=CreateWindowA("STATIC","Esperando al cliente...",WS_VISIBLE|WS_CHILD,
                18,203,345,34,hwnd,NULL,g_module,NULL);
            HWND controls[]={title,serverLabel,accountLabel,g_user,passLabel,g_pass,button,g_status};
            for(int i=0;i<8;i++)if(controls[i])SendMessageA(controls[i],WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
            SendMessageA(g_user,EM_LIMITTEXT,15,0);
            SendMessageA(g_pass,EM_LIMITTEXT,14,0);
            SetTimer(hwnd,1,500,NULL);return 0;
        }
        case WM_TIMER:
            if(Ready()) {
                GameWindowInfo game=ResolveGameWindow();
                g_gameWindow=game.hwnd;
                if(game.hwnd && !g_windowSizeChecked) {
                    // Only attempt a one-time recovery if the window is
                    // obviously collapsed into the narrow line shown by 5065.
                    RecoverCollapsedGameWindow(game);
                    InterlockedExchange(&g_windowSizeChecked,1);
                    game=ResolveGameWindow();
                }
                if(!g_hook && game.thread) {
                    g_nativeGameThread=game.thread;
                    g_hook=SetWindowsHookExA(WH_GETMESSAGE,OnGameMessage,g_module,g_nativeGameThread);
                }
                char status[160]={};
                if(!game.hwnd) {
                    Status("Login listo; buscando ventana grafica de Conquer...");
                } else if(game.height<180) {
                    wsprintfA(status,"Ventana del juego colapsada (%ldx%ld).",game.width,game.height);
                    Status(status);
                } else {
                    wsprintfA(status,g_hook ?
                        "Juego %ldx%ld - login nativo listo." :
                        "Juego %ldx%ld - esperando hilo grafico...", game.width,game.height);
                    Status(status);
                }
            } else Status("Buscando el objeto del login en el cliente...");
            return 0;
        case WM_COMMAND:
            if(LOWORD(w)==103 && HIWORD(w)==BN_CLICKED) {
                if(!Ready() || !g_hook){Status("El login interno aun no esta disponible.");return 0;}
                ZeroMemory(g_account,sizeof(g_account));
                SecureZeroMemory(g_password,sizeof(g_password));
                GetWindowTextA(g_user,g_account,sizeof(g_account));
                GetWindowTextA(g_pass,g_password,sizeof(g_password));
                if(!g_account[0] || !g_password[0]){Status("Ingresa cuenta y contrasena.");return 0;}
                if(InterlockedCompareExchange(&g_pending,1,0)==0) {
                    if(PostThreadMessageA(g_nativeGameThread,kSubmit,0,0))
                        Status("Autenticando mediante el cliente original...");
                    else {
                        InterlockedExchange(&g_pending,0);
                        SecureZeroMemory(g_password,sizeof(g_password));
                        Status("Fallo el envio al hilo del juego.");
                    }
                }
                return 0;
            }
            return 0;
        case WM_CLOSE: ShowWindow(hwnd,SW_HIDE);return 0;
        case WM_DESTROY: KillTimer(hwnd,1);PostQuitMessage(0);return 0;
    }
    return DefWindowProcA(hwnd,message,w,l);
}
DWORD WINAPI NativeUI(LPVOID) {
    WNDCLASSA c={};
    c.hInstance=g_module;c.lpszClassName="ReduxNative5065";c.lpfnWndProc=UiProc;
    c.hCursor=LoadCursor(NULL,IDC_ARROW);c.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_BTNFACE+1);
    if(!RegisterClassA(&c) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS)return 1;
    HWND window=CreateWindowExA(WS_EX_APPWINDOW,"ReduxNative5065","Redux 5065 - Sin Adobe Flash",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_VISIBLE,
        CW_USEDEFAULT,CW_USEDEFAULT,395,285,NULL,NULL,g_module,NULL);
    if(!window)return 2;
    g_loginWindow=window;
    MSG msg={};
    while(GetMessageA(&msg,NULL,0,0)>0) {
        if(!IsDialogMessageA(window,&msg)){TranslateMessage(&msg);DispatchMessageA(&msg);}
    }
    return 0;
}
}
bool EnableFlashless5065(HMODULE module) {
    Trace("Starting SHA-256 and PE validation for native 5065 login.");
    if(!ExactBuild()) { Trace("ERROR: executable hash/PE/signature validation failed; no patch applied."); return false; }
    g_module=module;
    GetPrivateProfileStringA("CLHook","SERVERNAME","Redux",g_server,sizeof(g_server),szConfig);
    // The version test belongs to the Flash ActiveX path, not network auth.
    const BYTE success[]={0xb0,0x01,0xc3}; // mov al,1; ret
    if(!WriteCode(g_image+kFlashCheckRva,success,sizeof(success))) {
        Trace("ERROR: verified Flash version check could not be patched."); return false;
    }
    Trace("Verified Flash version check bypassed; no Flash/COM hooks will be installed.");
    HANDLE ui=CreateThread(NULL,0,NativeUI,NULL,0,NULL);
    if(!ui) { Trace("ERROR: native Win32 login thread could not be created."); return false; }
    CloseHandle(ui);
    Trace("Native Win32 login thread created.");
    return true;
}
