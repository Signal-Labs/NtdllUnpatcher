// NtdllUnpatcher_Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <filesystem>
#include "NtdllUnpatcher.h"
#include <atlconv.h>

BOOL Dll_Injection(TCHAR *dll_name, int processId)
{
	TCHAR lpdllpath[MAX_PATH];
	GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);
	/* this portion get it and puts it in the memory of the remote process */
	// get size of the dll's path
	auto size = wcslen(lpdllpath) * sizeof(TCHAR);

	// open selected process
	auto hVictimProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, processId);
	if (hVictimProcess == NULL) // check if process open failed
	{
		return FALSE;
	}
	// allocate memory in the remote process
	auto pNameInVictimProcess = VirtualAllocEx(hVictimProcess,
		nullptr,
		size,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pNameInVictimProcess == NULL) //Check if allocation failed
	{
		return FALSE;
	}
	// write the DLL to memory
	auto bStatus = WriteProcessMemory(hVictimProcess,
		pNameInVictimProcess,
		lpdllpath,
		size,
		nullptr);
	if (bStatus == 0)
	{
		return FALSE;
	}
	// gets a handle for kernel32dll's LoadLibrary call
	auto hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		return FALSE;
	}
	auto LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == NULL)
	{
		if ((LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA")) == NULL)
		{
			return FALSE;
		}
	}

	// Using the above objects execute the DLL in the remote process
	auto hThreadId = CreateRemoteThread(hVictimProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)LoadLibraryAddress,
		pNameInVictimProcess,
		NULL,
		NULL);
	if (hThreadId == NULL)
	{
		return FALSE;
	}
	WaitForSingleObject(hThreadId, INFINITE);

	CloseHandle(hVictimProcess);
	VirtualFreeEx(hVictimProcess, pNameInVictimProcess, size, MEM_RELEASE);
	return TRUE;
}

int main(int argc, char* argv[])
{
	USES_CONVERSION;
	if (argc < 2)
	{
		printf_s("Usage: ./InjectProc.exe <path/to/dll> <pid>\nExample:\n\
		./InjectProc.exe path/to/dll.dll 655\n\
		");
		return EXIT_FAILURE;
	}
	__declspec(dllimport) BOOL InitializeHooks();
	BOOL res = InitializeHooks();
	if (!res)
	{
		return EXIT_FAILURE;
	}
	Dll_Injection(A2T(argv[1]), atoi(argv[2]));
	return EXIT_SUCCESS;
}