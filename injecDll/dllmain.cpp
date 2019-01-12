/*
*	Source of "InjecDll.dll"
*
*   BIG CREDIT TO "MinHook - The Minimalistic API Hooking Library for x64/x86" - BY Tsuda Kageyu.
*   Visit his GitHub Repository here: https://github.com/TsudaKageyu/minhook
*
*/


#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <dbghelp.h>
#include <MinHook.h>
#include <mutex>
#include <vector>
#include <thread>
#include <tlhelp32.h>
#include <string>
#include <intrin.h>
#include <Psapi.h>
#pragma intrinsic(_ReturnAddress)
#define MAX 500 //the max malloc calls

/*
*define and init arrays for malloc and free hook, each modle wuth unic hook funcs. the malloc and free func type etc.
*/
typedef void* (__cdecl *MallocTypeArr)(size_t);
typedef void(__cdecl *FreeTypeArr)(void *);
MallocTypeArr mallocHookFuncs[MAX];
FreeTypeArr freeHookFuncs[MAX];
MallocTypeArr TrampolineToMallocs[MAX];
FreeTypeArr TrampolineToFrees[MAX];
FILE * fp;
/*
*Init profile task to save the mallocs
*/
struct MallocProfile {
	size_t size;			//Save the size of the malloc
	void* memAdrr;			//save the address in the Heap
	void * retAdd;	//the return add for the calling func
	bool free = false;		//If the malloc release. Init with False
	size_t esp;
};
MallocProfile profMallocArr[MAX];//array for program malloc calls

struct FreeProfile {
	void* memAdrr;			//save the address in the Heap
	void* retAdd;	//the return add for the calling func
	bool free = false;		//If the malloc release. Init with False
};
FreeProfile ProfFreeArr[MAX];
/*
*The number for the moudles hooking
*/
int numUsedMallocHooksFuncs = 0;
int numUsedFreeHooksFuncs = 0;
/*
*The number of program malloc/free calls
*/
int numProgMalloc = 0;
int numProgFree = 0;

//Detour function for 'malloc'
template <int N>
void * __cdecl mallocHookfunc(size_t size) {

	int tmp;
	_asm
	{
		mov eax, [esp]
		mov tmp, eax
	}

	void * p = TrampolineToMallocs[N](size);
	profMallocArr[numProgMalloc].size = size;
	profMallocArr[numProgMalloc].memAdrr = p;
	profMallocArr[numProgMalloc].retAdd = _ReturnAddress();
	profMallocArr[numProgMalloc].esp = tmp;
	//printf("Return address from %s: %p\n", __FUNCTION__, _ReturnAddress());
	numProgMalloc++;
	return p;
}

//Detour function for 'free'
template <int N>
void  __cdecl freeHookfunc(void * p)
{
	TrampolineToFrees[N](p);
	ProfFreeArr[numProgFree].memAdrr = p;
	numProgFree++;
}

// Template recursion to init a hook table.
template<int N> struct InitNHooks {
	static void initHook() {
		InitNHooks<N - 1>::initHook();  // Compile time recursion. 
		mallocHookFuncs[N - 1] = &mallocHookfunc<N - 1>;
		freeHookFuncs[N - 1] = &freeHookfunc<N - 1>;
	}
};

template<> struct InitNHooks<0> {
	static void initHook() {
		// stop the recursion
	}
};

BOOL CALLBACK enumSymbolsCallback(PSYMBOL_INFO symbolInfo, ULONG symbolSize, PVOID userContext) {
	PCSTR moduleName = (PCSTR)userContext;
	// Hook mallocs.
	if (strcmp(symbolInfo->Name, "malloc") == 0) {

		if (numUsedMallocHooksFuncs >= MAX) {
			printf("All malloc hooks used up!\n");
			return true;
		}
		printf("HeapHop found 'malloc' in module %s\n", moduleName);
		if (bool stat = MH_CreateHook((void*)symbolInfo->Address, mallocHookFuncs[numUsedMallocHooksFuncs], (void **)&TrampolineToMallocs[numUsedMallocHooksFuncs]) != MH_OK) {
			printf("Create hook malloc failed!\n");
		}
		//printf("%d", stat);
		if (MH_EnableHook((void*)symbolInfo->Address) != MH_OK) {
			printf("Enable malloc hook failed!\n");
		}
		numUsedMallocHooksFuncs++;
	}
	//Hooks Free.
	if (strcmp(symbolInfo->Name, "free") == 0) {

		if (numUsedFreeHooksFuncs >= MAX) {
			printf("All free hooks used up!\n");
			return true;
		}
		printf("HeapHop found 'malloc' in module %s\n", moduleName);
		/*
		// MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
		//
		// Creates a Hook for the specified target function, in disabled state.
		// Parameters:
		//   pTarget    [in]  A pointer to the target function, which will be
		//                    overridden by the detour function.
		//   pDetour    [in]  A pointer to the detour function, which will override
		//                    the target function.
		//   ppOriginal [out] A pointer to the trampoline function, which will be
		//                    used to call the original target function.
		//                    This parameter can be NULL.
		*/
		if (MH_CreateHook((void*)symbolInfo->Address, freeHookFuncs[numUsedFreeHooksFuncs], (void **)&TrampolineToFrees[numUsedFreeHooksFuncs]) != MH_OK) {
			printf("Create hook free failed!\n");
		}

		if (MH_EnableHook((void*)symbolInfo->Address) != MH_OK) {
			printf("Enable free hook failed!\n");
		}
		numUsedFreeHooksFuncs++;
	}

}

BOOL CALLBACK enumModulesCallback(PCSTR ModuleName, DWORD_PTR BaseOfDll, PVOID UserContext) {
	//printf("%s\n", ModuleName);
	//if (strcmp(ModuleName, "ucrtbased") == 0) return true;
	SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "malloc", enumSymbolsCallback, (void*)ModuleName);
	SymEnumSymbols(GetCurrentProcess(), BaseOfDll, "free", enumSymbolsCallback, (void*)ModuleName);
	return true;
}

void printLog()
{
	int NotFree = 0;

	fopen_s(&fp, "log.txt", "w");
	for (int i = 0; i < numProgFree; i++)
	{
		for (int j = 0; j < numProgMalloc; j++)
		{
			if (ProfFreeArr[i].memAdrr == profMallocArr[j].memAdrr)
			{
				profMallocArr[j].free = true;
				ProfFreeArr[i].memAdrr = 0;		// In case we got "malloc,free,malloc" -> make sure we don't get true for the second malloc
												// allocated where the first was. (It actually happens!)
			}
		}
	}

	fprintf(fp, "HeapHop found the following calls to 'malloc':\n");

	double MegaByte = 1024 * 1024;
	int size;
	for (int i = 0; i < numProgMalloc; i++)
	{
		if(profMallocArr[i].esp != 0)
		{ 
			size = (int)(profMallocArr[i].size);
			fprintf(fp, "%d malloc(%d)\t", i, size);
			fprintf(fp, "memory allocated at: %d\t the return adress is %x.\n", profMallocArr[i].memAdrr, (unsigned int)profMallocArr[i].retAdd - 1);
		}
	}

	fprintf(fp, "\nHeapHop found 'free' calls for the following 'malloc' calls:\n");
	for (int i = 0; i < numProgMalloc; i++)
	{
		if (profMallocArr[i].esp != 0)
		{
			void *tmp = profMallocArr[i].memAdrr;
			if (!profMallocArr[i].free) {
				fprintf(fp, "#%d. could not find a mathching call to 'free' for:  malloc(%d) at %d, THIS CALL LEAKS\n", i, profMallocArr[i].size, profMallocArr[i].memAdrr);
				NotFree += (int)(profMallocArr[i].size);
			}
			else
			{
				fprintf(fp, "#%d. found a mathching call to 'free' for:  malloc(%d) at %d\n", i, profMallocArr[i].size, profMallocArr[i].memAdrr);
			}
		}
	}
	/*for (int i = 0; i < f; i++)
	{
		fprintf(fp, "%d Free address: %d\n",i, Mfree[i]);
	}*/
	fprintf(fp, "\n\n==============================HeapHop Monitor==============================\n");
	if (NotFree) {
		fprintf(fp, "HeapHop Monitor Found a Memory Leak\nIn total, %d Bytes aren't de-allocated.\n", NotFree);
		//printf("the number of the malloc %d\n", numProgMalloc);
		//printf("the number of the free %d", numProgFree);
	}
	else
	{
		fprintf(fp, "HeapHop Monitor did not Found a Memory Leak\n");
		//printf("\nthe number of the malloc %d\n", numProgMalloc);
		//printf("the number of the free %d", numProgFree);
	}


}


void setup()
{
	//printf("Injecting library...\n");
	InitNHooks<MAX>::initHook();
	// Init min hook framework.
	MH_Initialize();
	if (!SymInitialize(GetCurrentProcess(), NULL, true))
		printf("SymInitialize failed\n");
	//std::cout << "the Moudels: " << std::endl;
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
		setup();
		break;
	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		//printLog();
		break;
	case DLL_PROCESS_DETACH:
		MH_DisableHook(MH_ALL_HOOKS);
		printLog();
		// Perform any necessary cleanup.



		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
