#pragma once
#include <windows.h>
// Experimental Flash-free native login for the user's exact Conquer 5065 build.
// Never registers or loads Flash.ocx.
bool EnableFlashless5065(HMODULE module);
// Keeps the original SWF login, but bypasses the obsolete Flash version gate
// in memory after exact SHA-256/PE/byte validation of the supported 5065 EXE.
bool EnableLocalFlashCompatibility5065();
