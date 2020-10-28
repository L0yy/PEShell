#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


typedef BOOL(WINAPI* M_VirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef HMODULE(WINAPI* M_GetModuleHandleA)(
	_In_opt_ LPCSTR lpModuleName
	);

typedef HMODULE(WINAPI* M_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef FARPROC(WINAPI* M_GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);

typedef LPVOID(WINAPI* M_VirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD flAllocationType,
	_In_     DWORD flProtect
	);




typedef struct _M_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	UNICODE_STRING DllName;
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} M_LDR_DATA_TABLE_ENTRY, * PM_LDR_DATA_TABLE_ENTRY;

typedef struct _M_FUNC_TABLE
{
	PVOID mf_GetProcessAddress;
	PVOID mf_LoadlibraryA;
	PVOID mf_VirtualProtect;
	PVOID mf_GetModuleHandleA;
	PVOID mf_VirtualAlloc;

}M_FUNC_TABLE, * PM_FUNC_TABLE;


typedef struct PESTRUCT
{
	IMAGE_DATA_DIRECTORY IAT;

	IMAGE_DATA_DIRECTORY ROC;

	DWORD OEP;

	DWORD oldImageBase;

	PVOID mem_pe_base;//这里随意

	PM_FUNC_TABLE pm_func_table;//这个值在这个没用，借来用用



}Pestruct, * PPestruct;

//typedef struct PESTRUCT
//{
//	IMAGE_DATA_DIRECTORY IAT;
//
//	IMAGE_DATA_DIRECTORY ROC;
//
//	PVOID mem_pe_base;//这里随意
//
//	PM_FUNC_TABLE pm_func_table;//这个值在这个没用，借来用用
//
//	DWORD OEP;
//
//	DWORD oldImageBase;
//
//}Pestruct, * PPestruct;


_declspec(dllexport)  void start();

size_t
m_GetHash(const char*, BOOL);

VOID AntiDebug();

PCHAR Getbase();

Pestruct GetStruct(PCHAR);

PIMAGE_NT_HEADERS GetNTHeader(PVOID);

VOID DecryptExc(Pestruct);

PM_FUNC_TABLE GetBaseApi(PVOID, M_FUNC_TABLE);

PIMAGE_EXPORT_DIRECTORY m_GetImptable(PVOID);

PVOID m_GetDllBaseFromFs(size_t);

BOOL FixROC(Pestruct);

BOOL FixIAT(Pestruct);

BOOL JmpToOep(DWORD);

DWORD HookIAT(DWORD, PVOID);