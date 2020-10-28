#pragma once
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <locale.h>

typedef struct PESTRUCT
{
	IMAGE_DATA_DIRECTORY IAT;

	IMAGE_DATA_DIRECTORY ROC;

	DWORD OEP;

	DWORD oldImageBase;

	PVOID mem_pe_base;

	PIMAGE_OPTIONAL_HEADER m_dwpOptHeader;


}Pestruct;

typedef struct STRUCTUNPACKER
{
	PVOID pNewDllTextSec;

	INT dwSecSize;

	DWORD unpackerStartfunc;

}StructUnPacker;


Pestruct InitStuct(Pestruct m_pestruct);


BOOL IsDebug;

//LPWSTR DllPath = TEXT("C:\\Users\\Cray\\Desktop\\encrypting-shell\\Release\\Packdll.dll");
LPWSTR DllPath = TEXT(".\\Packdll.dll");

//LPWSTR FilePath = TEXT("C:\\Users\\Cray\\Desktop\\encrypting-shell\\Release\\demo.exe");
wchar_t FilePath[MAX_PATH] = { 0, };

PVOID LoadFile2Mem(LPWSTR m_pSouceFile);
BOOL Run(LPWSTR sourceFile);
VOID DecryptExc(Pestruct);
VOID ClearI_AT_ROC(Pestruct);
StructUnPacker LoadPackdll();
VOID ConstructNewPE(Pestruct, StructUnPacker);

PIMAGE_DOS_HEADER GetDosHeader(PVOID m_dwpPeBase);
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase);
PIMAGE_FILE_HEADER GetFileHeader(PVOID m_dwpPeBase);
PIMAGE_OPTIONAL_HEADER GetOptHeader(PVOID m_dwpPeBase);
PIMAGE_SECTION_HEADER GetSecionheader(PVOID m_dwpPeBase);

INT GetAlignment(INT Alignment, INT FixValue);

int __CRTDECL mprintf(
	_In_z_ _Printf_format_string_ char const* const _Format,
	...);
