//#pragma comment(lib, "injecDll.lib")
// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
//#include "Hooker.h"
// for 'SymInitialize' and friends
#include <iostream>
#include <dbghelp.h>
#include <MinHook.h>
#include <mutex>
#include <vector>
#include <thread>
#include <tlhelp32.h>


typedef void* (__cdecl *PtrMalloc)(size_t);
typedef void(__cdecl *PtrFree)(void *);
const int numHooks = 128;
PtrMalloc mallocHooks[numHooks];
PtrFree freeHooks[numHooks];
PtrMalloc originalMallocs[numHooks];
PtrFree originalFrees[numHooks];

PtrMalloc originalMallocs1;
std::mutex hookTableMutex;
int nUsedMallocHooks = 0;
int nUsedFreeHooks = 0;


// Malloc hook function. 

void * __cdecl mallocHook1(size_t size) {

	void * p = originalMallocs1(size);
	printf("%d\n", size);
	printf("XXXXXXXXX\n");
	return p;
}

BOOL CALLBACK enumSymbolsCallback(PSYMBOL_INFO symbolInfo, ULONG symbolSize, PVOID userContext) {
	std::cout << "the symbol: ";
	printf(symbolInfo->Name);
	printf("\n");
	std::lock_guard<std::mutex> lk(hookTableMutex);

	PCSTR moduleName = (PCSTR)userContext;

	// Hook mallocs.
	if (strcmp(symbolInfo->Name, "malloc") == 0) {

		if (nUsedMallocHooks >= numHooks) {
			printf("All malloc hooks used up!\n");
			return true;
		}
		//&mallocHook,reinterpret_cast<LPVOID*>(&fpMalloc)
		printf("Hooking malloc from module %s into malloc hook num %d.\n", moduleName, nUsedMallocHooks);
		if (MH_CreateHook((void*)symbolInfo->Address, mallocHook1, (void **)&originalMallocs1) != MH_OK) {
			printf("Create hook malloc failed!\n");
		}
		
		if (MH_EnableHook((void*)symbolInfo->Address) != MH_OK) {
			printf("Enable malloc hook failed!\n");
		}
		nUsedMallocHooks++;
	}
}

BOOL CALLBACK enumModulesCallback(PCSTR ModuleName, DWORD_PTR BaseOfDll, PVOID UserContext) {
	printf(ModuleName);
	printf("\n");
	//if (strcmp(ModuleName, "injecDll.dll") == 0)
		//return true;
	//if (strcmp(ModuleName, "msvcrt") == 0)
		//return true;

	SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "malloc", enumSymbolsCallback, (void*)ModuleName);
	//SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "free", enumSymbolsCallback, (void*)ModuleName);
	return true;
}

void setup()
{
	printf("Injecting library...\n");

	nUsedMallocHooks = 0;
	nUsedFreeHooks = 0;

	InitNHooks<numHooks>::initHook();

	// Init min hook framework.
	MH_Initialize();

	if (!SymInitialize(GetCurrentProcess(), NULL, true))
		printf("SymInitialize failed\n");
	std::cout << "the Moudels: " << std::endl;
	SymEnumerateModules(GetCurrentProcess(), enumModulesCallback, NULL);
}



extern "C" BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)  // reserved
{
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		//countMallocFree();
		setup()
		//trynewMalloc();
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
