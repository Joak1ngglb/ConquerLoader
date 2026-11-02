#pragma once
#include "stdafx.h"
#include <windows.h>
#include <objbase.h>
#include "detours.h"

class CFlashFix {
public:
    typedef HMODULE (WINAPI* HookLoadLibrary)(LPCWSTR,HANDLE,DWORD);
    typedef HRESULT (WINAPI* HookCoCreateInstance)(REFCLSID,LPUNKNOWN,DWORD,REFIID,LPVOID*);
    typedef HRESULT (WINAPI* HookCoGetClassObject)(REFCLSID,DWORD,COSERVERINFO*,REFIID,LPVOID*);
    typedef HRESULT (WINAPI* HookCLSIDFromProgID)(LPCOLESTR,LPCLSID);
    enum ActivationStage {
        StageNotStarted=0,StageInstallingHooks,StageHooksActive,StagePreflight,
        StageLoadingOcx,StageClassFactory,StageCreateInstance,StageReady,StageFailed
    };

    static HookLoadLibrary pLoadLibrary;
    static HookCoCreateInstance pCoCreateInstance;
    static HookCoGetClassObject pCoGetClassObject;
    static HookCLSIDFromProgID pCLSIDFromProgID;

    static HRESULT Hook(bool enableComFallback=true);
    static HRESULT PreflightLocalControl();
    static void PublishStartupFailure();
    static const char* StageName();
    static HMODULE WINAPI LoadLibraryDetour(LPCWSTR,HANDLE,DWORD);
    static HRESULT WINAPI CoCreateInstanceDetour(REFCLSID,LPUNKNOWN,DWORD,REFIID,LPVOID*);
    static HRESULT WINAPI CoGetClassObjectDetour(REFCLSID,DWORD,COSERVERINFO*,REFIID,LPVOID*);
    static HRESULT WINAPI CLSIDFromProgIDDetour(LPCOLESTR,LPCLSID);
};
