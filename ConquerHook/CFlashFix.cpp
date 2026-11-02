/*
 * Local Flash.ocx loader for Conquer Online 5065.
 * Based on the original LoadLibraryExW redirect posted by Ultimation:
 * https://www.elitepvpers.com/forum/co2-guides-templates/4858018-release-flash-fix-old-clients.html
 *
 * Additional local COM factory routing addresses clients without a globally
 * registered ShockwaveFlash ActiveX control. No registry writes; no installers.
 * The OCX remains third-party executable code: test untrusted ones in a VM.
 */
#include "stdafx.h"
#include "CFlashFix.h"
#include <shlwapi.h>
#include <cwchar>
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")

CFlashFix::HookLoadLibrary CFlashFix::pLoadLibrary = NULL;
CFlashFix::HookCoCreateInstance CFlashFix::pCoCreateInstance = NULL;
CFlashFix::HookCoGetClassObject CFlashFix::pCoGetClassObject = NULL;
CFlashFix::HookCLSIDFromProgID CFlashFix::pCLSIDFromProgID = NULL;

namespace {
    const CLSID kShockwaveFlash =
        {0xd27cdb6e, 0xae6d, 0x11cf, {0x96, 0xb8, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
    HMODULE g_localFlash = NULL;

    // Resolve next to Conquer.exe (never relative to the caller's cwd).
    bool LocalFlashPath(wchar_t output[MAX_PATH]) {
        DWORD n = GetModuleFileNameW(NULL, output, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return false;
        wchar_t* last = wcsrchr(output, L'\\');
        if (!last) return false;
        // Preserve the directory separator; append the OCX after it.
        const wchar_t name[] = L"Flash.ocx";
        const size_t prefix = static_cast<size_t>(last + 1 - output);
        if (prefix + (sizeof(name) / sizeof(wchar_t)) > MAX_PATH) return false;
        wcscpy_s(last + 1, MAX_PATH - prefix, name);
        DWORD attr = GetFileAttributesW(output);
        return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool FlashClass(REFCLSID clsid) {
        return IsEqualCLSID(clsid, kShockwaveFlash) != FALSE;
    }

    bool FlashProgID(LPCOLESTR progId) {
        if (!progId) return false;
        const wchar_t name[] = L"ShockwaveFlash.ShockwaveFlash";
        size_t length = (sizeof(name) / sizeof(wchar_t)) - 1;
        return _wcsnicmp(progId, name, length) == 0 &&
            (progId[length] == L'\0' || progId[length] == L'.');
    }

    HMODULE OpenLocalFlash() {
        HMODULE module = reinterpret_cast<HMODULE>(
            InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(&g_localFlash),
                                              NULL, NULL));
        if (module) return module;
        wchar_t path[MAX_PATH] = {};
        if (!LocalFlashPath(path)) return NULL;
        // pLoadLibrary is a Detours trampoline after Hook() succeeds.
        HMODULE loaded = CFlashFix::pLoadLibrary
            ? CFlashFix::pLoadLibrary(path, NULL, 0) : LoadLibraryW(path);
        if (!loaded) return NULL;
        PVOID old = InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(&g_localFlash), loaded, NULL);
        if (old) {
            FreeLibrary(loaded);
            return reinterpret_cast<HMODULE>(old);
        }
        return loaded;
    }

    typedef HRESULT (STDAPICALLTYPE* DllGetClassObjectProc)(
        REFCLSID, REFIID, LPVOID*);
    HRESULT LocalFlashClassFactory(REFCLSID clsid, REFIID iid, LPVOID* result) {
        if (!result) return E_POINTER;
        *result = NULL;
        if (!FlashClass(clsid)) return CLASS_E_CLASSNOTAVAILABLE;
        HMODULE module = OpenLocalFlash();
        if (!module) return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
        DllGetClassObjectProc getFactory = reinterpret_cast<DllGetClassObjectProc>(
            GetProcAddress(module, "DllGetClassObject"));
        if (!getFactory) return CLASS_E_CLASSNOTAVAILABLE;
        return getFactory(clsid, iid, result);
    }
}

void CFlashFix::Hook(bool enableComFallback) {
    HMODULE kernel = GetModuleHandleW(L"kernelbase.dll");
    HMODULE ole = GetModuleHandleW(L"ole32.dll");
    if (!kernel) return;
    pLoadLibrary = reinterpret_cast<HookLoadLibrary>(
        GetProcAddress(kernel, "LoadLibraryExW"));
    if (!pLoadLibrary) return;

    if (ole && enableComFallback) {
        pCoCreateInstance = reinterpret_cast<HookCoCreateInstance>(
            GetProcAddress(ole, "CoCreateInstance"));
        pCoGetClassObject = reinterpret_cast<HookCoGetClassObject>(
            GetProcAddress(ole, "CoGetClassObject"));
        pCLSIDFromProgID = reinterpret_cast<HookCLSIDFromProgID>(
            GetProcAddress(ole, "CLSIDFromProgID"));
    }

    if (DetourTransactionBegin() != NO_ERROR) return;
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&pLoadLibrary), LoadLibraryDetour);
    if (pCoCreateInstance)
        DetourAttach(reinterpret_cast<PVOID*>(&pCoCreateInstance), CoCreateInstanceDetour);
    if (pCoGetClassObject)
        DetourAttach(reinterpret_cast<PVOID*>(&pCoGetClassObject), CoGetClassObjectDetour);
    if (pCLSIDFromProgID)
        DetourAttach(reinterpret_cast<PVOID*>(&pCLSIDFromProgID), CLSIDFromProgIDDetour);
    LONG status = DetourTransactionCommit();
    if (status != NO_ERROR)
        OutputDebugStringA("[Redux5065] Flash OCX redirection could not be installed.\n");
    else
        OutputDebugStringA("[Redux5065] Local Flash OCX/COM redirect active.\n");
}

HMODULE WINAPI CFlashFix::LoadLibraryDetour(
    LPCWSTR filename, HANDLE file, DWORD flags) {
    if (filename && StrStrIW(filename, L"Flash.ocx")) {
        wchar_t local[MAX_PATH] = {};
        if (LocalFlashPath(local))
            return pLoadLibrary(local, file, flags);
    }
    return pLoadLibrary(filename, file, flags);
}

HRESULT WINAPI CFlashFix::CoGetClassObjectDetour(
    REFCLSID clsid, DWORD context, COSERVERINFO* server, REFIID iid, LPVOID* result) {
    if (FlashClass(clsid) && (context & CLSCTX_INPROC_SERVER) && server == NULL) {
        HRESULT hr = LocalFlashClassFactory(clsid, iid, result);
        if (SUCCEEDED(hr)) return hr;
    }
    return pCoGetClassObject(clsid, context, server, iid, result);
}

HRESULT WINAPI CFlashFix::CoCreateInstanceDetour(
    REFCLSID clsid, LPUNKNOWN outer, DWORD context, REFIID iid, LPVOID* result) {
    if (FlashClass(clsid) && (context & CLSCTX_INPROC_SERVER) && result) {
        IClassFactory* factory = NULL;
        HRESULT hr = LocalFlashClassFactory(clsid, IID_IClassFactory,
                                             reinterpret_cast<void**>(&factory));
        if (SUCCEEDED(hr) && factory) {
            *result = NULL;
            hr = factory->CreateInstance(outer, iid, result);
            factory->Release();
            if (SUCCEEDED(hr)) return hr;
        }
    }
    return pCoCreateInstance(clsid, outer, context, iid, result);
}

HRESULT WINAPI CFlashFix::CLSIDFromProgIDDetour(
    LPCOLESTR progId, LPCLSID clsid) {
    if (clsid && FlashProgID(progId)) {
        *clsid = kShockwaveFlash;
        return S_OK;
    }
    return pCLSIDFromProgID(progId, clsid);
}
