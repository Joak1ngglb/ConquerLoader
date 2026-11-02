// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

extern void csv3_init(HMODULE hModule);
extern void csv3_shutdown();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		csv3_init(hModule);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if(lpReserved==NULL)csv3_shutdown();
		break;
	}
	return TRUE;
}

