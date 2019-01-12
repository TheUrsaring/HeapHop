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

CRITICAL_SECTION ghCritical;


typedef void* (__cdecl *PtrMalloc)(size_t);
typedef void(__cdecl *PtrFree)(void *);
const int numHooks = 5;
PtrMalloc mallocHooks[numHooks];
PtrFree freeHooks[numHooks];
PtrMalloc originalMallocs[numHooks];
PtrFree originalFrees[numHooks];
PtrMalloc originalMallocs1;
PtrFree originalFrees1;
std::mutex hookTableMutex;
int nUsedMallocHooks = 0;
int nUsedFreeHooks = 0;

 struct product {
	size_t size;
	void* address;
};
product mallocs[numHooks];

// Malloc hook function. 

void * __cdecl mallocHook1(size_t size) {
	void * p = originalMallocs1(size);
	//mallocs[nUsedMallocHooks].address = p;
	//mallocs[nUsedMallocHooks].size = size;
	printf("Into the size: %d\n", mallocs[nUsedMallocHooks].size);
	printf("Into the address: %d\n", mallocs[nUsedMallocHooks].address);
	return p;
}
void  __cdecl freeHook1(void * p) {
	originalFrees1(p);
	/*for (int i = 0; i <= nUsedMallocHooks;i++)
	{
		if (mallocs[i].address == p)
		{
			mallocs[i].size = 0;
		}
	}*/
}

void * __cdecl mallocHook2(size_t size) {
	void * p = originalMallocs1(size);
	mallocs[nUsedMallocHooks].address = p;
	mallocs[nUsedMallocHooks].size = size;
	printf("Into the size: %d\n", mallocs[nUsedMallocHooks].size);
	printf("Into the address: %d\n", mallocs[nUsedMallocHooks].address);
	return p;
}
void  __cdecl freeHook2(void * p) {
	originalFrees1(p);
	for (int i = 0; i <= nUsedMallocHooks; i++)
	{
		if (mallocs[i].address == p)
		{
			mallocs[i].size = 0;
		}
	}
}

void init() {
	for (int i = 0; i <= numHooks; i++)
	{
		mallocs[i].size = 0;
		mallocs[i].address = 0;
	}
}
bool check()
{
	for (int i = 0; i <= numHooks; i++)
	{
		if (mallocs[i].size != 0)
			return 1;
	}
	return 0;

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

	if (strcmp(symbolInfo->Name, "free") == 0) {

		if (nUsedFreeHooks >= numHooks) {
			printf("All free hooks used up!\n");
			return true;
		}
		//&mallocHook,reinterpret_cast<LPVOID*>(&fpMalloc)
		printf("Hooking free from module %s into free hook num %d.\n", moduleName, nUsedMallocHooks);
		if (MH_CreateHook((void*)symbolInfo->Address, freeHook1, (void **)&originalFrees1) != MH_OK) {
			printf("Create hook malloc failed!\n");
		}

		if (MH_EnableHook((void*)symbolInfo->Address) != MH_OK) {
			printf("Enable free hook failed!\n");
		}

		nUsedFreeHooks++;
	}

}

BOOL CALLBACK enumModulesCallback(PCSTR ModuleName, DWORD_PTR BaseOfDll, PVOID UserContext) {
	printf(ModuleName);
	printf("\n");
	if (strcmp(ModuleName, "injecDll") == 0)
		return true;
	
	SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "malloc", enumSymbolsCallback, (void*)ModuleName);

	//SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "free", enumSymbolsCallback, (void*)ModuleName);
	return true;
}

void setup()
{
	printf("Injecting library...\n");
	InitializeCriticalSection(&ghCritical);
	nUsedMallocHooks = 0;
	nUsedFreeHooks = 0;
	

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
		init();
		setup();
		if (check())
		{
			printf("XXXXXXX\n");
		}
		else
		{
			printf("VVVVVVVVVV\n");
		}
		for (int i = 0; i <= numHooks; i++)
		{
			printf("the size: %d\n", mallocs[i].size);
			printf("the address: %d\n", mallocs[i].address);
		}

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
