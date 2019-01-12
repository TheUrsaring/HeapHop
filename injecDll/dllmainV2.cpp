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




#define HOOKERDLL_API __declspec(dllexport)



typedef void* (__cdecl *PtrMalloc)(size_t);
typedef void(__cdecl *PtrFree)(void *);
const int numHooks = 128;
PtrMalloc mallocHooks[numHooks];
PtrFree freeHooks[numHooks];
PtrMalloc originalMallocs[numHooks];
PtrMalloc originalMallocs1;
PtrFree originalFrees[numHooks];
std::mutex hookTableMutex;
int nUsedMallocHooks = 0;
int nUsedFreeHooks = 0;


// Malloc hook function. Templated so we can hook many mallocs.
template <int N>
void * __cdecl mallocHook(size_t size) {

	void * p = originalMallocs[N](size);
	printf("XXXXXXXXX\n");
	return p;
}

void * __cdecl mallocHook1(size_t size) {

	void * p = originalMallocs1(size);
	printf("%d\n", size);
	printf("XXXXXXXXX\n");
	return p;
}

// Template recursion to init a hook table.
template<int N> struct InitNHooks {
	static void initHook() {
		InitNHooks<N - 1>::initHook();  // Compile time recursion. 

		mallocHooks[N - 1] = &mallocHook<N - 1>;
	}
};

template<> struct InitNHooks<0> {
	static void initHook() {
		// stop the recursion
	}
};






PtrMalloc fpMalloc = NULL;
// Detour function which overrides Hmalloc.
void* __cdecl DetourHmalloc(size_t size)
{
	printf("tryHook\n");

	return fpMalloc(size);
}

int trynewMalloc()
{
	printf("try_Hook\n");
	// Initialize MinHook.
	if (MH_Initialize() != MH_OK)
	{
		return 1;
	}

	// Create a hook for MessageBoxW, in disabled state.
	if (MH_CreateHook(&malloc, &DetourHmalloc,
		reinterpret_cast<LPVOID*>(&fpMalloc)) != MH_OK)
	{
		return 1;
	}

	// or you can use the new helper function like this.
	//if (MH_CreateHookApiEx(
	//    L"user32", "MessageBoxW", &DetourMessageBoxW, &fpMessageBoxW) != MH_OK)
	//{
	//    return 1;
	//}

	// Enable the hook for MessageBoxW.
	if (MH_EnableHook(&malloc) != MH_OK)
	{
		return 1;
	}
	// Expected to tell "Hooked!".

	// Disable the hook for MessageBoxW.
	//if (MH_DisableHook(&malloc) != MH_OK)
	//{
	//	return 1;
	//}

	//// Expected to not tell "Not hooked...".

	//// Uninitialize MinHook.
	//if (MH_Uninitialize() != MH_OK)
	//{
	//	return 1;
	//}
	return 0;
}

// Malloc hook function. 
void * __cdecl mallocHook(size_t size) {
	printf("safafas");
	return malloc(size);
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

extern "C" HOOKERDLL_API void countMallocFree()
{
	printf("Hello from dll: countMallocFree!\n");

	// Retrieves a pseudo handle for the current process.
	HANDLE thisProc = GetCurrentProcess();

	// Initializes the symbol handler for a process.
	if (!SymInitialize(thisProc, NULL, 1)) // might need to change '1' to 'true'
	{
		printf("SymIntialize failed :-(\n");
	}
	printf("SymIntialize succeeded :-)\n");
	/*

		//Enumerates all symbols in a process.
		if (!SymEnumSymb(
		thisProc,			// handler to the process.
		0,
		*!*,				// combination of the last two lines means: Enumerate in all modules!
		NULL,				// TODO: implement CALLBACK and send it here.
		NULL,				// argument for the callback.
		))
		{
		printf("SymEnumSymb failed :-(\n");
		}
		*/
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



// code from: https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-entry-point-function
// DllMain define an entry point to the dll which behave acorrding to the 'fdwReason' argument.
// Without 'exetern "C" ' our C client cannot use this method.
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
		setup();
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
