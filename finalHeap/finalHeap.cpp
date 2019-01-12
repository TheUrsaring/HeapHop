#include <Windows.h>
#include <Psapi.h>
#include <strsafe.h>
#include <iostream>
#include <stdio.h>
#include <conio.h>
#include <thread>
#include <string>
#include <algorithm>


/* 
*	HeapHop - Memory leak detector.
*	Copyright (C) 2019 - Michael Cohen & Zvei Eliezer Nir.
*   All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*   1. Redistributions of source code must retain the above copyright
*      notice, this list of conditions and the following disclaimer.
*   2. Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
*  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
*  PARTICULAR PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDER
*  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
*  EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO,
*  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
*  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING
*  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


std::string getDirectoryOfFile(const std::string &file) {
	size_t pos = (std::min)(file.find_last_of("/"), file.find_last_of("\\"));
	if (pos == std::string::npos)
		return ".";
	else
		return file.substr(0, pos);
}

extern "C" int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cout << "error, need two args" << std::endl;
		return -1;
	}
	char* injectExePath = argv[1];
	std::string heapyInjectDllName = "injecDll.dll";
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);//exePath - A pointer to a buffer that receives the fully qualified path of the module (current Moudle).
	//std::cout << "the current Path is: " + std::string(exePath) << std::endl;
	DWORD flags = CREATE_SUSPENDED;//init the Process in a suspended status


	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	GetStartupInfoA(&si);

	if (CreateProcessA(NULL, injectExePath, NULL, NULL, 0, flags, NULL, (LPSTR)".", &si, &pi) == 0) {
		std::cout << "Error creating process " << injectExePath << std::endl;
		return -1;
	}
	//now there is a suspended process lets inject our dll

	/*
	 * Get address of the LoadLibrary function.
	 */
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
	}

	/*
	 * Allocate new memory region inside the process's address space.
	 */
	std::string dllPath = getDirectoryOfFile(std::string(exePath)) + "\\" + heapyInjectDllName;

	LPVOID arg = (LPVOID)VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath.c_str()), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("Error: the memory could not be allocated inside the chosen process.\n");
	}

	/*
	 * Write the argument to LoadLibraryA to the process's newly allocated memory region.
	 */
	int n = WriteProcessMemory(pi.hProcess, arg, dllPath.c_str(), strlen(dllPath.c_str()), NULL);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space.\n");
	}

	/*
	 * Inject our DLL into the process's address space.
	 */
	HANDLE threadID = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created.\n");
	}
	else {
		printf("Dll injection succeeded.\n");
	}

	// Wait for the thread to finish.
	WaitForSingleObject(threadID, INFINITE);

	// Lets see what it says...
	DWORD dwThreadExitCode = 0;
	GetExitCodeThread(threadID, &dwThreadExitCode);
	CloseHandle(threadID);

	/*
	 * Close the handle to the process, becuase we've already injected the DLL.
	 */
	CloseHandle(pi.hProcess);

	VirtualFreeEx(addr, arg, 0, MEM_RELEASE);

	SetThreadDescription(pi.hThread, (PCWSTR)"input_thread");
	ResumeThread(pi.hThread);

	printf("HeapHop is about to terminate. Type: 'type log.txt' to see the results in the log file.\n\n");

	return 0;
}