/*
 * Registry-free local Flash ActiveX activation for Conquer Online 5065.
 * Hooks are process-local. Flash.ocx is never registered and Conquer.exe is
 * never modified on disk.
 */
#include "stdafx.h"
#include "CFlashFix.h"
#include <shlwapi.h>
#include <winver.h>
#include <cwchar>
#include <cstdarg>
#include <cstdio>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

CFlashFix::HookLoadLibrary CFlashFix::pLoadLibrary = NULL;
CFlashFix::HookCoCreateInstance CFlashFix::pCoCreateInstance = NULL;
CFlashFix::HookCoGetClassObject CFlashFix::pCoGetClassObject = NULL;
CFlashFix::HookCLSIDFromProgID CFlashFix::pCLSIDFromProgID = NULL;

namespace {
const CLSID kShockwaveFlash =
    {0xd27cdb6e,0xae6d,0x11cf,{0x96,0xb8,0x44,0x45,0x53,0x54,0x00,0x00}};
HMODULE g_localFlash = NULL;
SRWLOCK g_flashLock = SRWLOCK_INIT;
volatile LONG g_hookState = 0;
volatile LONG g_stage = CFlashFix::StageNotStarted;
HANDLE g_readyEvent = NULL;
HANDLE g_failedEvent = NULL;
__declspec(thread) bool g_insideLocalLoad = false;

// This referenced import guarantees that ole32.dll is loaded before
// CLHook.dll receives PROCESS_ATTACH during the early APC.
CFlashFix::HookCoCreateInstance g_forceOle32Import = &::CoCreateInstance;

void Trace(const char* format, ...) {
    char message[768]={};
    va_list args; va_start(args,format);
    vsprintf_s(message,sizeof(message),format,args);
    va_end(args);
    char path[MAX_PATH]={};
    DWORD n=GetModuleFileNameA(NULL,path,MAX_PATH);
    if(!n || n>=MAX_PATH)return;
    char* slash=strrchr(path,'\\');
    if(!slash)return;
    strcpy_s(slash+1,MAX_PATH-(slash+1-path),"CLHook-5065.log");
    HANDLE file=CreateFileA(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return;
    char line[896]={};
    int length=sprintf_s(line,"%lu [tid=%lu] [flash:%s] %s\r\n",GetTickCount(),
        GetCurrentThreadId(),CFlashFix::StageName(),message);
    DWORD written=0;
    if(length>0)WriteFile(file,line,static_cast<DWORD>(length),&written,NULL);
    CloseHandle(file);
}
void TraceHr(const char* operation,HRESULT hr) {
    Trace("%s => HRESULT=0x%08lX (%s)",operation,static_cast<unsigned long>(hr),
        SUCCEEDED(hr)?"success":"failure");
}
void GuidText(REFGUID guid,char output[64]) {
    sprintf_s(output,64,"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1,guid.Data2,guid.Data3,guid.Data4[0],guid.Data4[1],guid.Data4[2],
        guid.Data4[3],guid.Data4[4],guid.Data4[5],guid.Data4[6],guid.Data4[7]);
}
void SetStage(CFlashFix::ActivationStage stage) {
    InterlockedExchange(&g_stage,static_cast<LONG>(stage));
}
void PublishOutcome(bool ready) {
    wchar_t name[96]={};
    swprintf_s(name,L"Local\\ConquerLoader-Flash5065-%s-%lu",
        ready?L"Ready":L"Failed",GetCurrentProcessId());
    HANDLE& eventHandle=ready?g_readyEvent:g_failedEvent;
    if(!eventHandle)eventHandle=CreateEventW(NULL,TRUE,FALSE,name);
    if(eventHandle)SetEvent(eventHandle);
    Trace("Published startup outcome event: %s.",ready?"Ready":"Failed");
}
bool LocalFlashPath(wchar_t output[MAX_PATH]) {
    DWORD n=GetModuleFileNameW(NULL,output,MAX_PATH);
    if(!n || n>=MAX_PATH)return false;
    wchar_t* last=wcsrchr(output,L'\\');
    if(!last)return false;
    const wchar_t name[]=L"Flash.ocx";
    const size_t prefix=static_cast<size_t>(last+1-output);
    if(prefix+(sizeof(name)/sizeof(name[0]))>MAX_PATH)return false;
    wcscpy_s(last+1,MAX_PATH-prefix,name);
    DWORD attributes=GetFileAttributesW(output);
    return attributes!=INVALID_FILE_ATTRIBUTES && !(attributes&FILE_ATTRIBUTE_DIRECTORY);
}
bool FlashClass(REFCLSID clsid) {
    return IsEqualCLSID(clsid,kShockwaveFlash)!=FALSE;
}
bool FlashProgID(LPCOLESTR progId) {
    if(!progId)return false;
    const wchar_t name[]=L"ShockwaveFlash.ShockwaveFlash";
    const size_t length=(sizeof(name)/sizeof(name[0]))-1;
    return _wcsnicmp(progId,name,length)==0 &&
        (progId[length]==L'\0' || progId[length]==L'.');
}
bool ValidatePe32(const wchar_t* path) {
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE){Trace("Flash.ocx open failed, Win32=%lu",GetLastError());return false;}
    IMAGE_DOS_HEADER dos={}; DWORD read=0; bool valid=false;
    if(ReadFile(file,&dos,sizeof(dos),&read,NULL) && read==sizeof(dos) &&
       dos.e_magic==IMAGE_DOS_SIGNATURE && dos.e_lfanew>0 &&
       SetFilePointer(file,dos.e_lfanew,NULL,FILE_BEGIN)!=INVALID_SET_FILE_POINTER) {
        DWORD signature=0; IMAGE_FILE_HEADER header={};
        valid=ReadFile(file,&signature,sizeof(signature),&read,NULL) && read==sizeof(signature) &&
            signature==IMAGE_NT_SIGNATURE && ReadFile(file,&header,sizeof(header),&read,NULL) &&
            read==sizeof(header) && header.Machine==IMAGE_FILE_MACHINE_I386;
    }
    CloseHandle(file);
    Trace("Flash.ocx PE validation: %s",valid?"x86 valid":"invalid/not x86");
    return valid;
}
void TraceVersion(const wchar_t* path) {
    DWORD ignored=0; DWORD size=GetFileVersionInfoSizeW(path,&ignored);
    if(!size){Trace("Flash.ocx version resource unavailable, Win32=%lu",GetLastError());return;}
    BYTE* data=new BYTE[size];
    VS_FIXEDFILEINFO* info=NULL; UINT length=0;
    if(GetFileVersionInfoW(path,0,size,data) &&
       VerQueryValueW(data,L"\\",reinterpret_cast<void**>(&info),&length) && info) {
        Trace("Flash.ocx version %u.%u.%u.%u",HIWORD(info->dwFileVersionMS),
            LOWORD(info->dwFileVersionMS),HIWORD(info->dwFileVersionLS),LOWORD(info->dwFileVersionLS));
    } else Trace("Flash.ocx version query failed, Win32=%lu",GetLastError());
    delete[] data;
}
HMODULE OpenLocalFlash() {
    HMODULE existing=reinterpret_cast<HMODULE>(InterlockedCompareExchangePointer(
        reinterpret_cast<PVOID volatile*>(&g_localFlash),NULL,NULL));
    if(existing)return existing;
    AcquireSRWLockExclusive(&g_flashLock);
    existing=g_localFlash;
    DWORD failure=ERROR_SUCCESS;
    if(!existing) {
        wchar_t path[MAX_PATH]={};
        if(!LocalFlashPath(path)) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            failure=ERROR_FILE_NOT_FOUND;
            Trace("Flash.ocx is missing beside Conquer.exe.");
        } else if(!ValidatePe32(path)) {
            SetLastError(ERROR_BAD_EXE_FORMAT);
            failure=ERROR_BAD_EXE_FORMAT;
        } else {
            TraceVersion(path);
            SetStage(CFlashFix::StageLoadingOcx);
            Trace("Loading local Flash.ocx with LOAD_WITH_ALTERED_SEARCH_PATH.");
            CFlashFix::HookLoadLibrary loader=CFlashFix::pLoadLibrary;
            g_insideLocalLoad=true;
            existing=loader ? loader(path,NULL,LOAD_WITH_ALTERED_SEARCH_PATH) :
                LoadLibraryExW(path,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);
            failure=existing?ERROR_SUCCESS:GetLastError();
            g_insideLocalLoad=false;
            if(existing) {
                g_localFlash=existing;
                Trace("Flash.ocx loaded at 0x%p; no COM registration used.",existing);
            } else Trace("Flash.ocx LoadLibraryExW failed, Win32=%lu",failure);
        }
    }
    ReleaseSRWLockExclusive(&g_flashLock);
    if(!existing)SetLastError(failure?failure:ERROR_MOD_NOT_FOUND);
    return existing;
}
typedef HRESULT (STDAPICALLTYPE* DllGetClassObjectProc)(REFCLSID,REFIID,LPVOID*);
HRESULT LocalFlashClassFactory(REFCLSID clsid,REFIID iid,LPVOID* result) {
    if(!result)return E_POINTER;
    *result=NULL;
    if(!FlashClass(clsid))return CLASS_E_CLASSNOTAVAILABLE;
    char requestedIid[64]={}; GuidText(iid,requestedIid);
    Trace("Local DllGetClassObject request IID=%s.",requestedIid);
    HMODULE module=OpenLocalFlash();
    if(!module)return HRESULT_FROM_WIN32(GetLastError()?GetLastError():ERROR_MOD_NOT_FOUND);
    DllGetClassObjectProc getFactory=reinterpret_cast<DllGetClassObjectProc>(
        GetProcAddress(module,"DllGetClassObject"));
    if(!getFactory){Trace("Flash.ocx does not export DllGetClassObject, Win32=%lu",GetLastError());return CLASS_E_CLASSNOTAVAILABLE;}
    SetStage(CFlashFix::StageClassFactory);
    HRESULT hr=getFactory(clsid,iid,result);
    TraceHr("Flash.ocx!DllGetClassObject",hr);
    return hr;
}
}

const char* CFlashFix::StageName() {
    switch(InterlockedCompareExchange(&g_stage,0,0)) {
        case StageInstallingHooks:return "install-hooks";
        case StageHooksActive:return "hooks-active";
        case StagePreflight:return "preflight";
        case StageLoadingOcx:return "load-ocx";
        case StageClassFactory:return "class-factory";
        case StageCreateInstance:return "create-instance";
        case StageReady:return "ready";
        case StageFailed:return "failed";
        default:return "not-started";
    }
}

HRESULT CFlashFix::Hook(bool enableComFallback) {
    LONG prior=InterlockedCompareExchange(&g_hookState,1,0);
    if(prior==2)return S_FALSE;
    if(prior!=0)return E_PENDING;
    SetStage(StageInstallingHooks);
    Trace("Hook begin; COM fallback=%s; forced ole32 import=0x%p.",
        enableComFallback?"enabled":"disabled",g_forceOle32Import);
    HMODULE kernel=GetModuleHandleW(L"kernelbase.dll");
    if(!kernel)kernel=GetModuleHandleW(L"kernel32.dll");
    HMODULE ole=GetModuleHandleW(L"ole32.dll");
    Trace("Modules: kernel=0x%p ole32=0x%p.",kernel,ole);
    if(!kernel || (enableComFallback && !ole)) {
        Trace("Required module missing; hooks not installed.");
        SetStage(StageFailed); InterlockedExchange(&g_hookState,-1); PublishOutcome(false);
        return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
    }
    pLoadLibrary=reinterpret_cast<HookLoadLibrary>(GetProcAddress(kernel,"LoadLibraryExW"));
    if(enableComFallback) {
        pCoCreateInstance=reinterpret_cast<HookCoCreateInstance>(GetProcAddress(ole,"CoCreateInstance"));
        pCoGetClassObject=reinterpret_cast<HookCoGetClassObject>(GetProcAddress(ole,"CoGetClassObject"));
        pCLSIDFromProgID=reinterpret_cast<HookCLSIDFromProgID>(GetProcAddress(ole,"CLSIDFromProgID"));
    }
    Trace("Exports: LoadLibraryExW=0x%p CoCreateInstance=0x%p CoGetClassObject=0x%p CLSIDFromProgID=0x%p.",
        pLoadLibrary,pCoCreateInstance,pCoGetClassObject,pCLSIDFromProgID);
    if(!pLoadLibrary || (enableComFallback &&
       (!pCoCreateInstance || !pCoGetClassObject || !pCLSIDFromProgID))) {
        SetStage(StageFailed); InterlockedExchange(&g_hookState,-1); PublishOutcome(false);
        return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    }
    LONG status=DetourTransactionBegin();
    if(status==NO_ERROR)status=DetourUpdateThread(GetCurrentThread());
    if(status==NO_ERROR)status=DetourAttach(reinterpret_cast<PVOID*>(&pLoadLibrary),LoadLibraryDetour);
    if(status==NO_ERROR && pCoCreateInstance)
        status=DetourAttach(reinterpret_cast<PVOID*>(&pCoCreateInstance),CoCreateInstanceDetour);
    if(status==NO_ERROR && pCoGetClassObject)
        status=DetourAttach(reinterpret_cast<PVOID*>(&pCoGetClassObject),CoGetClassObjectDetour);
    if(status==NO_ERROR && pCLSIDFromProgID)
        status=DetourAttach(reinterpret_cast<PVOID*>(&pCLSIDFromProgID),CLSIDFromProgIDDetour);
    if(status==NO_ERROR)status=DetourTransactionCommit();
    else DetourTransactionAbort();
    if(status!=NO_ERROR) {
        Trace("Detours installation failed, status=%ld.",status);
        SetStage(StageFailed); InterlockedExchange(&g_hookState,-1); PublishOutcome(false);
        return HRESULT_FROM_WIN32(status);
    }
    InterlockedExchange(&g_hookState,2); SetStage(StageHooksActive);
    Trace("LoadLibraryExW and COM activation hooks committed atomically.");
    return S_OK;
}

HRESULT CFlashFix::PreflightLocalControl() {
    SetStage(StagePreflight);
    Trace("Starting local OCX preflight outside loader lock.");
    IClassFactory* factory=NULL;
    HRESULT hr=LocalFlashClassFactory(kShockwaveFlash,IID_IClassFactory,
        reinterpret_cast<void**>(&factory));
    if(SUCCEEDED(hr) && !factory)hr=E_UNEXPECTED;
    if(factory)factory->Release();
    if(SUCCEEDED(hr)){SetStage(StageReady);Trace("Preflight complete: local ShockwaveFlash class factory ready.");PublishOutcome(true);}
    else {SetStage(StageFailed);TraceHr("Preflight local class factory",hr);PublishOutcome(false);}
    return hr;
}

HMODULE WINAPI CFlashFix::LoadLibraryDetour(LPCWSTR filename,HANDLE file,DWORD flags) {
    if(g_insideLocalLoad)return pLoadLibrary(filename,file,flags);
    if(filename) {
        LPCWSTR base=PathFindFileNameW(filename);
        if(base && _wcsicmp(base,L"Flash.ocx")==0) {
            wchar_t local[MAX_PATH]={};
            if(LocalFlashPath(local)) {
                Trace("LoadLibraryExW redirect requested (flags=0x%08lX).",flags);
                return pLoadLibrary(local,file,flags);
            }
        }
    }
    return pLoadLibrary(filename,file,flags);
}

HRESULT WINAPI CFlashFix::CoGetClassObjectDetour(REFCLSID clsid,DWORD context,
    COSERVERINFO* server,REFIID iid,LPVOID* result) {
    if(FlashClass(clsid) && (context&CLSCTX_INPROC_SERVER) && server==NULL) {
        char requestedIid[64]={}; GuidText(iid,requestedIid);
        Trace("CoGetClassObject intercepted for ShockwaveFlash; context=0x%08lX IID=%s.",context,requestedIid);
        HRESULT hr=LocalFlashClassFactory(clsid,iid,result);
        TraceHr("CoGetClassObject local result",hr);
        return hr;
    }
    return pCoGetClassObject(clsid,context,server,iid,result);
}

HRESULT WINAPI CFlashFix::CoCreateInstanceDetour(REFCLSID clsid,LPUNKNOWN outer,
    DWORD context,REFIID iid,LPVOID* result) {
    if(FlashClass(clsid) && (context&CLSCTX_INPROC_SERVER)) {
        if(!result)return E_POINTER;
        *result=NULL;
        char requestedIid[64]={}; GuidText(iid,requestedIid);
        Trace("CoCreateInstance intercepted for ShockwaveFlash; context=0x%08lX outer=0x%p IID=%s.",context,outer,requestedIid);
        IClassFactory* factory=NULL;
        HRESULT hr=LocalFlashClassFactory(clsid,IID_IClassFactory,
            reinterpret_cast<void**>(&factory));
        if(SUCCEEDED(hr) && factory) {
            SetStage(StageCreateInstance);
            hr=factory->CreateInstance(outer,iid,result);
            factory->Release();
            TraceHr("IClassFactory::CreateInstance",hr);
            if(SUCCEEDED(hr))SetStage(StageReady); else SetStage(StageFailed);
        }
        return hr;
    }
    return pCoCreateInstance(clsid,outer,context,iid,result);
}

HRESULT WINAPI CFlashFix::CLSIDFromProgIDDetour(LPCOLESTR progId,LPCLSID clsid) {
    if(clsid && FlashProgID(progId)) {
        *clsid=kShockwaveFlash;
        Trace("CLSIDFromProgID intercepted for local ShockwaveFlash ProgID.");
        return S_OK;
    }
    return pCLSIDFromProgID(progId,clsid);
}
