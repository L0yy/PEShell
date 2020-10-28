#include "header.h"





//************************************
// ��������: LoadFile2Mem
// ����˵��: ���ر��ӿǳ����ڴ棬δչ��
// ��������: LPWSTR m_pSouceFile
// �� �� ֵ: PVOID ���汻�ӿǵ�һ���ڴ�
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PVOID LoadFile2Mem(LPWSTR m_pSouceFile)
{
	HANDLE hFile = CreateFile(m_pSouceFile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		mprintf("loadFileToMem_CrateFile!");

		return NULL;
	}

	DWORD m_dwFileSize = GetFileSize(hFile, NULL);

	PVOID pPeBase = malloc(m_dwFileSize * sizeof(BYTE));
	memset(pPeBase, 0, m_dwFileSize);

	DWORD dwRead = 0;

	ReadFile(hFile, pPeBase, m_dwFileSize, &dwRead, NULL);

	CloseHandle(hFile);

	return pPeBase;
}


//************************************
// ��������: GetDosHeader
// ����˵��: ���Dosͷ
// ��������: PVOID m_dwpPeBase
// �� �� ֵ: PIMAGE_DOS_HEADER
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PIMAGE_DOS_HEADER GetDosHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_DOS_HEADER)m_dwpPeBase;
}

//************************************
// ��������: GetNTHeader
// ����˵��: ���Ntͷ
// ��������: PVOID m_dwpPeBase
// �� �� ֵ: PIMAGE_NT_HEADERS
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_NT_HEADERS)((PBYTE)GetDosHeader(m_dwpPeBase)->e_lfanew + (DWORD)m_dwpPeBase);
}


//************************************
// ��������: GetFileHeader
// ����˵��: ��ȡ�ļ�ͷ
// ��������: PVOID m_dwpPeBase
// �� �� ֵ: PIMAGE_FILE_HEADER
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PIMAGE_FILE_HEADER GetFileHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_FILE_HEADER)((PBYTE)GetNTHeader(m_dwpPeBase) + 4);
}


//************************************
// ��������: GetOptHeader
// ����˵��: ���optͷ
// ��������: PVOID m_dwpPeBase
// �� �� ֵ: PIMAGE_OPTIONAL_HEADER
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PIMAGE_OPTIONAL_HEADER GetOptHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_OPTIONAL_HEADER)((PBYTE)GetFileHeader(m_dwpPeBase) + sizeof(IMAGE_FILE_HEADER));
}


//************************************
// ��������: GetSecionheader
// ����˵��: ���Secͷ
// ��������: PVOID m_dwpPeBase
// �� �� ֵ: PIMAGE_SECTION_HEADER
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
PIMAGE_SECTION_HEADER GetSecionheader(PVOID m_dwpPeBase)
{
	return IMAGE_FIRST_SECTION(GetNTHeader(m_dwpPeBase));
}

//************************************
// ��������: GetAlignment
// ����˵��: ������룬�¼ӽڵ�ʱ��Ҫ��
// ��������: INT Alignment  FileAlignment or SectionAlignmen
// ��������: INT FixValue   Need to fix value
// �� �� ֵ: INT
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
INT GetAlignment(INT Alignment, INT FixValue)
{
	return FixValue % Alignment == 0 ? FixValue : (FixValue / Alignment + 1) * Alignment;

}

//************************************
// ��������: DecryptExc
// ����˵��: ���ܴ���Σ����ܷ�ʽ Key = timestap^0x12344321
// ��������: Pestruct m_pestruct
// �� �� ֵ: VOID
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
VOID DecryptExc(Pestruct m_pestruct)
{
	DWORD start = 0;
	DWORD end = 0;
	PDWORD FileStart = 0;
	DWORD Encryptsize = 0;
	INT i = 0;

	DWORD encryptKey =
		GetFileHeader(m_pestruct.mem_pe_base)->TimeDateStamp;

	encryptKey = encryptKey ^ 0x12344321;

	DWORD entrypoint =
		m_pestruct.m_dwpOptHeader->AddressOfEntryPoint;

	PIMAGE_SECTION_HEADER Psec = IMAGE_FIRST_SECTION(GetNTHeader(m_pestruct.mem_pe_base));
	INT SecNumber = GetFileHeader(m_pestruct.mem_pe_base)->NumberOfSections;

	for (; SecNumber > 0; SecNumber--)
	{
		start = Psec->VirtualAddress;
		end = Psec->VirtualAddress + Psec->SizeOfRawData;

		if (entrypoint >= start &
			entrypoint <= end)
		{
			Encryptsize = Psec->SizeOfRawData;

			FileStart =
				(PCHAR)(m_pestruct.mem_pe_base) + Psec->PointerToRawData;

			break;
		}
		Psec++;
	}

	for (i = 0; 4 * i < Encryptsize;i++)
	{
		if (*FileStart)
		{
			*FileStart = *FileStart ^ encryptKey;

			encryptKey = encryptKey << 25 | encryptKey >> 7;
		}

		FileStart++;

	}

}


//************************************
// ��������: ClearI_AT_ROC
// ����˵��: �ѱ��ӿǵ�ԭʼIAT �� ROC����Ĩ��
// ��������: Pestruct m_pestruct
// �� �� ֵ: VOID
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
VOID ClearI_AT_ROC(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader->DataDirectory[1].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[1].Size = 0;

	m_pestruct.m_dwpOptHeader->DataDirectory[5].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[5].Size = 0;

	//������import address Table directory �������ز�����
	m_pestruct.m_dwpOptHeader->DataDirectory[12].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[12].Size = 0;

}

//************************************
// ��������: InitStuct
// ����˵��: ����IAT��ROC ����֮���Ǵ���ʹ��
// ��������: Pestruct m_pestruct
// �� �� ֵ: Pestruct
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
Pestruct InitStuct(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader =
		GetOptHeader(m_pestruct.mem_pe_base);   //�����ڴ��е�PE

	m_pestruct.OEP = m_pestruct.m_dwpOptHeader->AddressOfEntryPoint;//����ԭʼ��ڵ�RVA

	m_pestruct.IAT =
		m_pestruct.m_dwpOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IDA����

	m_pestruct.ROC =
		m_pestruct.m_dwpOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; // �ض�λ����

	m_pestruct.oldImageBase = m_pestruct.m_dwpOptHeader->ImageBase;
	return m_pestruct;
}


//************************************
// ��������: LoadPackdll
// ����˵��: ����packdll�Ĵ���ε��ڴ�
// �� �� ֵ: StructUnPacker
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
StructUnPacker LoadPackdll()
{
	StructUnPacker spack;

	HMODULE PDllBase = LoadLibrary(DllPath);

	DWORD unpackerStartfunc = (DWORD)GetProcAddress(PDllBase, "start");

	PIMAGE_SECTION_HEADER pFristSec = IMAGE_FIRST_SECTION(GetNTHeader((PVOID)PDllBase));

	INT dwSecSize = pFristSec->SizeOfRawData;

	PCHAR pDllTextSec = (PCHAR)PDllBase + pFristSec->VirtualAddress;

	PCHAR pNewDllTextSec = malloc(dwSecSize);

	memcpy_s(pNewDllTextSec, dwSecSize, pDllTextSec, dwSecSize);

	//�ڴ�����VA Ҫ�ȼ�ȥ��ֵ,Ȼ���ȥ����ڵ�va�����ܵõ�������������ڽ��ڵ�ƫ��
	spack.unpackerStartfunc = unpackerStartfunc - (DWORD)PDllBase - (DWORD)pFristSec->VirtualAddress;

	spack.dwSecSize = dwSecSize;

	spack.pNewDllTextSec = pNewDllTextSec;

	return spack;

}

//************************************
// ��������: mprintf
// ����˵��: �Լ������printf����ͨ��debugѡ��������
// ��������: _In_z_ _Printf_format_string_ char const * const _Format
// ��������: ...
// �� �� ֵ: int __CRTDECL
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
int __CRTDECL mprintf(
	_In_z_ _Printf_format_string_ char const* const _Format,
	...)
{
	if (IsDebug)
	{
		int _Result;
		va_list _ArgList;
		__crt_va_start(_ArgList, _Format);
		_Result = _vfprintf_l(stdout, _Format, NULL, _ArgList);
		__crt_va_end(_ArgList);
		return _Result;
	}
	else
	{
		return NULL;
	}
}



//************************************
// ��������: ConstructNewPE
// ����˵��: ���ڴ��й����µ�PE��Ȼ�󱣴浽�ļ���
// ��������: Pestruct m_pestruct
// ��������: StructUnPacker m_StrucUnPacker
// �� �� ֵ: VOID
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
VOID ConstructNewPE(Pestruct m_pestruct, StructUnPacker  m_StrucUnPacker)
{
	INT NumberOfSections =
		GetNTHeader(m_pestruct.mem_pe_base)->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pFirstSec =
		IMAGE_FIRST_SECTION(GetNTHeader(m_pestruct.mem_pe_base));

	PIMAGE_SECTION_HEADER plastSec =
		(PCHAR)pFirstSec + (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER);

	INT PeFileSize = (PCHAR)plastSec->PointerToRawData + plastSec->SizeOfRawData;

	INT SumNewPESize = PeFileSize + GetAlignment(m_pestruct.m_dwpOptHeader->FileAlignment, m_StrucUnPacker.dwSecSize);


	//�������һ���ڵ���Ϣ
	IMAGE_SECTION_HEADER pNewSec = { 0, };

	memcpy_s(pNewSec.Name, 8, "packer!", 8);

	pNewSec.PointerToRawData = PeFileSize;

	pNewSec.SizeOfRawData = GetAlignment(m_pestruct.m_dwpOptHeader->FileAlignment, m_StrucUnPacker.dwSecSize);

	pNewSec.VirtualAddress = m_pestruct.m_dwpOptHeader->SizeOfImage;

	pNewSec.Misc.VirtualSize = m_StrucUnPacker.dwSecSize;

	pNewSec.Characteristics = 0x60000020;

	*(PIMAGE_SECTION_HEADER)((PCHAR)plastSec + sizeof(IMAGE_SECTION_HEADER)) = pNewSec;


	//����PE�������ݵ�PE�� DOSͷ��
	PCHAR pDos2 = (PCHAR)m_pestruct.mem_pe_base + 2;

	memcpy_s(pDos2, 0x400, &m_pestruct, sizeof(m_pestruct));


	m_pestruct.m_dwpOptHeader->SizeOfImage =
		(PCHAR)pNewSec.VirtualAddress + GetAlignment(m_pestruct.m_dwpOptHeader->SectionAlignment, m_StrucUnPacker.dwSecSize);

	//sec++
	PIMAGE_NT_HEADERS pNT = GetNTHeader(m_pestruct.mem_pe_base);

	pNT->FileHeader.NumberOfSections = pNT->FileHeader.NumberOfSections + 1;

	pNT->OptionalHeader.AddressOfEntryPoint = pNewSec.VirtualAddress + m_StrucUnPacker.unpackerStartfunc;

	PCHAR pNewPE = malloc(SumNewPESize);

	ZeroMemory(pNewPE, SumNewPESize);

	//���������ܴ���
	memcpy_s(pNewPE, SumNewPESize, m_pestruct.mem_pe_base, PeFileSize);

	memcpy_s(pNewPE + PeFileSize, SumNewPESize, m_StrucUnPacker.pNewDllTextSec, m_StrucUnPacker.dwSecSize);

	FILE* fp = fopen("Packed.exe", "wb");

	fwrite(pNewPE, 1, SumNewPESize, fp);

	fclose(fp);


}


//************************************
// ��������: Run
// ����˵��: ִ�мӿǴ��������
// ��������: LPWSTR sourceFile
// �� �� ֵ: BOOL
// �� �� ��: Cray
// ��������: 2020/10/26
//************************************
BOOL Run(LPWSTR sourceFile)
{

	Pestruct m_pestruct;

	m_pestruct.mem_pe_base = LoadFile2Mem(sourceFile);

	m_pestruct = InitStuct(m_pestruct);

	DecryptExc(m_pestruct);

	ClearI_AT_ROC(m_pestruct);

	StructUnPacker m_StrucUnPacker = LoadPackdll();

	ConstructNewPE(m_pestruct, m_StrucUnPacker);

	return TRUE;
}


int main(int argc, char* argv[])
{

#ifdef _DEBUG
	IsDebug = TRUE;
#endif 

	setlocale(LC_ALL, "chs");

	printf("[*] ������Ҫ�ӿǳ���:\n");
	_getws(FilePath);

	Run(FilePath);

	printf("[*] �ӿ���ɣ��Ѽӿǳ��򱣴���Packer.exe����Ŀ¼�£�\n[*] ��������˳�...");

	getchar();

	return 0;

}


