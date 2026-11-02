#pragma once
#include "stdafx.h"
#include <windows.h>
#include <objbase.h>
#include "detours.h"

// Flash loader for legacy Conquer clients. Only hooks the current Conquer
// process, and only redirects the ShockwaveFlash ActiveX class.
class CFlashFix {
public:
    typedef HMODULE (WINAPI* HookLoadLibrary)(LPCWSTR, HANDLE, DWORD);
    typedef HRESULT (WINAPI* HookCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    typedef HRESULT (WINAPI* HookCoGetClassObject)(REFCLSID, DWORD, COSERVERINFO*, REFIID, LPVOID*);
    typedef HRESULT (WINAPI* HookCLSIDFromProgID)(LPCOLESTR, LPCLSID);

    static HookLoadLibrary pLoadLibrary;
    static HookCoCreateInstance pCoCreateInstance;
    static HookCoGetClassObject pCoGetClassObject;
    static HookCLSIDFromProgID pCLSIDFromProgID;

    static void Hook();
    static HMODULE WINAPI LoadLibraryDetour(LPCWSTR filename, HANDLE file, DWORD flags);
    static HRESULT WINAPI CoCreateInstanceDetour(REFCLSID clsid, LPUNKNOWN outer,
        DWORD context, REFIID iid, LPVOID* result);
    static HRESULT WINAPI CoGetClassObjectDetour(REFCLSID clsid, DWORD context,
        COSERVERINFO* server, REFIID iid, LPVOID* result);
    static HRESULT WINAPI CLSIDFromProgIDDetour(LPCOLESTR progId, LPCLSID clsid);
};
