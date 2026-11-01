#include "stdafx.h"
#include "Flashless5065.h"
#include <windows.h>
#include <cstring>

// Reverse-engineered for the supplied PE32 dated 2008-08-24 ONLY.
// A mismatch fails closed, without patching arbitrary client versions.
extern "C" volatile PVOID g_nativeLoginObject = NULL;
extern "C" DWORD g_nativeGameThread = 0;
extern "C" void* g_ctorTrampoline = NULL;
namespace {
const DWORD kBase=0x00400000, kTimestamp=0x48b121fe, kSize=0x18f000;
const DWORD kConstructor=0x43121e, kFlashCheck=0x47a0b1, kNativeLogin=0x431e38;
const DWORD kLoginVtable=0x52d940;
const UINT kSubmit=WM_APP+5065;
HMODULE g_module=NULL;
HHOOK g_hook=NULL;
HWND g_user=NULL, g_pass=NULL, g_status=NULL;
char g_account[16]={0}, g_password[16]={0};
volatile LONG g_pending=0;

bool WriteCode(DWORD address,const void* data,size_t size) {
    DWORD previous=0, ignored=0;
    if(!VirtualProtect(reinterpret_cast<void*>(address),size,PAGE_EXECUTE_READWRITE,&previous))return false;
    memcpy(reinterpret_cast<void*>(address),data,size);
    FlushInstructionCache(GetCurrentProcess(),reinterpret_cast<void*>(address),size);
    VirtualProtect(reinterpret_cast<void*>(address),size,previous,&ignored);
    return true;
}
bool ExactBuild() {
    HMODULE module=GetModuleHandleA(NULL);
    if(reinterpret_cast<DWORD>(module)!=kBase)return false;
    PIMAGE_DOS_HEADER mz=reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    if(mz->e_magic!=IMAGE_DOS_SIGNATURE || mz->e_lfanew<0 || mz->e_lfanew>4096)return false;
    PIMAGE_NT_HEADERS32 nt=reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<BYTE*>(module)+mz->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 ||
       nt->FileHeader.TimeDateStamp!=kTimestamp || nt->OptionalHeader.SizeOfImage!=kSize)return false;
    const BYTE ctor[]={0xb8,0x91,0x9e,0x51,0x00,0xe8,0xf8,0xf0,0x0b,0x00};
    const BYTE check[]={0xb8,0x2d,0xda,0x51,0x00,0xe8,0x65,0x62,0x07,0x00};
    return memcmp(reinterpret_cast<void*>(kConstructor),ctor,sizeof(ctor))==0 &&
           memcmp(reinterpret_cast<void*>(kFlashCheck),check,sizeof(check))==0;
}
void __stdcall Capture(void* object) {
    g_nativeLoginObject=object;
    g_nativeGameThread=GetCurrentThreadId();
}
__declspec(naked) void CaptureCtor() {
    __asm {
        pushfd
        pushad
        push ecx
        call Capture
        popad
        popfd
        jmp dword ptr [g_ctorTrampoline]
    }
}
bool HookCtor() {
    BYTE* t=static_cast<BYTE*>(VirtualAlloc(NULL,16,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE));
    if(!t)return false;
    memcpy(t,reinterpret_cast<void*>(kConstructor),5);
    t[5]=0xe9;
    *reinterpret_cast<DWORD*>(t+6)=kConstructor+5-reinterpret_cast<DWORD>(t+10);
    g_ctorTrampoline=t;
    BYTE jump[5]={0xe9};
    *reinterpret_cast<DWORD*>(jump+1)=reinterpret_cast<DWORD>(&CaptureCtor)-(kConstructor+5);
    if(!WriteCode(kConstructor,jump,sizeof(jump))) {
        g_ctorTrampoline=NULL;
        VirtualFree(t,0,MEM_RELEASE);return false;
    }
    return true;
}
bool Ready() {
    BYTE* object=reinterpret_cast<BYTE*>(g_nativeLoginObject);
    if(!object)return false;
    MEMORY_BASIC_INFORMATION region={};
    if(!VirtualQuery(object,&region,sizeof(region)) || region.State!=MEM_COMMIT ||
       (region.Protect&(PAGE_NOACCESS|PAGE_GUARD)))return false;
    return *reinterpret_cast<DWORD*>(object)==kLoginVtable;
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
                (reinterpret_cast<GameLogin>(kNativeLogin))(self);
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
            HWND title=CreateWindowA("STATIC","Redux 5065 - Login sin Flash",
                WS_VISIBLE|WS_CHILD,18,15,330,24,hwnd,NULL,g_module,NULL);
            HWND accountLabel=CreateWindowA("STATIC","Cuenta:",WS_VISIBLE|WS_CHILD,
                18,57,88,23,hwnd,NULL,g_module,NULL);
            g_user=CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_AUTOHSCROLL,
                110,50,235,28,hwnd,reinterpret_cast<HMENU>(101),g_module,NULL);
            HWND passLabel=CreateWindowA("STATIC","Contrasena:",WS_VISIBLE|WS_CHILD,
                18,96,88,23,hwnd,NULL,g_module,NULL);
            g_pass=CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",WS_VISIBLE|WS_CHILD|WS_TABSTOP|ES_PASSWORD,
                110,89,235,28,hwnd,reinterpret_cast<HMENU>(102),g_module,NULL);
            HWND button=CreateWindowA("BUTTON","Entrar",WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_DEFPUSHBUTTON,
                110,135,235,32,hwnd,reinterpret_cast<HMENU>(103),g_module,NULL);
            g_status=CreateWindowA("STATIC","Esperando al cliente...",WS_VISIBLE|WS_CHILD,
                18,190,330,30,hwnd,NULL,g_module,NULL);
            HWND controls[]={title,accountLabel,g_user,passLabel,g_pass,button,g_status};
            for(int i=0;i<7;i++)if(controls[i])SendMessageA(controls[i],WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
            SendMessageA(g_user,EM_LIMITTEXT,15,0);
            SendMessageA(g_pass,EM_LIMITTEXT,14,0);
            SetTimer(hwnd,1,500,NULL);return 0;
        }
        case WM_TIMER:
            if(Ready()) {
                if(!g_hook && g_nativeGameThread)
                    g_hook=SetWindowsHookExA(WH_GETMESSAGE,OnGameMessage,g_module,g_nativeGameThread);
                Status(g_hook ? "Listo para autenticar con Redux." : "No se pudo enlazar al hilo del cliente.");
            } else Status("Esperando el login interno del cliente...");
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
        CW_USEDEFAULT,CW_USEDEFAULT,385,265,NULL,NULL,g_module,NULL);
    if(!window)return 2;
    MSG msg={};
    while(GetMessageA(&msg,NULL,0,0)>0) {
        if(!IsDialogMessageA(window,&msg)){TranslateMessage(&msg);DispatchMessageA(&msg);}
    }
    return 0;
}
}
bool EnableFlashless5065(HMODULE module) {
    if(!ExactBuild())return false;
    g_module=module;
    if(!HookCtor())return false;
    // The version test belongs to the Flash ActiveX path, not network auth.
    const BYTE success[]={0xb0,0x01,0xc3}; // mov al,1; ret
    if(!WriteCode(kFlashCheck,success,sizeof(success)))return false;
    HANDLE ui=CreateThread(NULL,0,NativeUI,NULL,0,NULL);
    if(!ui)return false;
    CloseHandle(ui);
    return true;
}
