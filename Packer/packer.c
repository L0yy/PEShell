#include "header.h"





//************************************
// 函数名称: LoadFile2Mem
// 函数说明: 加载被加壳程序到内存，未展开
// 函数参数: LPWSTR m_pSouceFile
// 返 回 值: PVOID 保存被加壳的一段内存
// 创 建 人: Cray
// 创建日期: 2020/10/26
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
// 函数名称: GetDosHeader
// 函数说明: 获得Dos头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_DOS_HEADER
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_DOS_HEADER GetDosHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_DOS_HEADER)m_dwpPeBase;
}

//************************************
// 函数名称: GetNTHeader
// 函数说明: 获得Nt头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_NT_HEADERS
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_NT_HEADERS)((PBYTE)GetDosHeader(m_dwpPeBase)->e_lfanew + (DWORD)m_dwpPeBase);
}


//************************************
// 函数名称: GetFileHeader
// 函数说明: 获取文件头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_FILE_HEADER
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_FILE_HEADER GetFileHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_FILE_HEADER)((PBYTE)GetNTHeader(m_dwpPeBase) + 4);
}


//************************************
// 函数名称: GetOptHeader
// 函数说明: 获得opt头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_OPTIONAL_HEADER
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_OPTIONAL_HEADER GetOptHeader(PVOID m_dwpPeBase)
{
	return (PIMAGE_OPTIONAL_HEADER)((PBYTE)GetFileHeader(m_dwpPeBase) + sizeof(IMAGE_FILE_HEADER));
}


//************************************
// 函数名称: GetSecionheader
// 函数说明: 获得Sec头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_SECTION_HEADER
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_SECTION_HEADER GetSecionheader(PVOID m_dwpPeBase)
{
	return IMAGE_FIRST_SECTION(GetNTHeader(m_dwpPeBase));
}

//************************************
// 函数名称: GetAlignment
// 函数说明: 计算对齐，新加节的时候要算
// 函数参数: INT Alignment  FileAlignment or SectionAlignmen
// 函数参数: INT FixValue   Need to fix value
// 返 回 值: INT
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
INT GetAlignment(INT Alignment, INT FixValue)
{
	return FixValue % Alignment == 0 ? FixValue : (FixValue / Alignment + 1) * Alignment;

}

//************************************
// 函数名称: DecryptExc
// 函数说明: 加密代码段，加密方式 Key = timestap^0x12344321
// 函数参数: Pestruct m_pestruct
// 返 回 值: VOID
// 创 建 人: Cray
// 创建日期: 2020/10/26
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
// 函数名称: ClearI_AT_ROC
// 函数说明: 把被加壳的原始IAT 和 ROC都给抹掉
// 函数参数: Pestruct m_pestruct
// 返 回 值: VOID
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
VOID ClearI_AT_ROC(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader->DataDirectory[1].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[1].Size = 0;

	m_pestruct.m_dwpOptHeader->DataDirectory[5].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[5].Size = 0;

	//不清理import address Table directory 程序会加载不起来
	m_pestruct.m_dwpOptHeader->DataDirectory[12].VirtualAddress = 0;
	m_pestruct.m_dwpOptHeader->DataDirectory[12].Size = 0;

}

//************************************
// 函数名称: InitStuct
// 函数说明: 保存IAT和ROC 供给之后解壳代码使用
// 函数参数: Pestruct m_pestruct
// 返 回 值: Pestruct
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
Pestruct InitStuct(Pestruct m_pestruct)
{

	m_pestruct.m_dwpOptHeader =
		GetOptHeader(m_pestruct.mem_pe_base);   //保存内存中的PE

	m_pestruct.OEP = m_pestruct.m_dwpOptHeader->AddressOfEntryPoint;//保存原始入口点RVA

	m_pestruct.IAT =
		m_pestruct.m_dwpOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IDA表项

	m_pestruct.ROC =
		m_pestruct.m_dwpOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; // 重定位表项

	m_pestruct.oldImageBase = m_pestruct.m_dwpOptHeader->ImageBase;
	return m_pestruct;
}


//************************************
// 函数名称: LoadPackdll
// 函数说明: 导入packdll的代码段到内存
// 返 回 值: StructUnPacker
// 创 建 人: Cray
// 创建日期: 2020/10/26
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

	//内存中是VA 要先减去基值,然后减去这个节的va，就能得到这个导出函数在节内的偏移
	spack.unpackerStartfunc = unpackerStartfunc - (DWORD)PDllBase - (DWORD)pFristSec->VirtualAddress;

	spack.dwSecSize = dwSecSize;

	spack.pNewDllTextSec = pNewDllTextSec;

	return spack;

}

//************************************
// 函数名称: mprintf
// 函数说明: 自己构造的printf，可通过debug选项控制输出
// 函数参数: _In_z_ _Printf_format_string_ char const * const _Format
// 函数参数: ...
// 返 回 值: int __CRTDECL
// 创 建 人: Cray
// 创建日期: 2020/10/26
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
// 函数名称: ConstructNewPE
// 函数说明: 在内存中构造新的PE，然后保存到文件中
// 函数参数: Pestruct m_pestruct
// 函数参数: StructUnPacker m_StrucUnPacker
// 返 回 值: VOID
// 创 建 人: Cray
// 创建日期: 2020/10/26
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


	//增加最后一个节的信息
	IMAGE_SECTION_HEADER pNewSec = { 0, };

	memcpy_s(pNewSec.Name, 8, "packer!", 8);

	pNewSec.PointerToRawData = PeFileSize;

	pNewSec.SizeOfRawData = GetAlignment(m_pestruct.m_dwpOptHeader->FileAlignment, m_StrucUnPacker.dwSecSize);

	pNewSec.VirtualAddress = m_pestruct.m_dwpOptHeader->SizeOfImage;

	pNewSec.Misc.VirtualSize = m_StrucUnPacker.dwSecSize;

	pNewSec.Characteristics = 0x60000020;

	*(PIMAGE_SECTION_HEADER)((PCHAR)plastSec + sizeof(IMAGE_SECTION_HEADER)) = pNewSec;


	//保存PE基本数据到PE的 DOS头中
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

	//拷贝被加密代码
	memcpy_s(pNewPE, SumNewPESize, m_pestruct.mem_pe_base, PeFileSize);

	memcpy_s(pNewPE + PeFileSize, SumNewPESize, m_StrucUnPacker.pNewDllTextSec, m_StrucUnPacker.dwSecSize);

	FILE* fp = fopen("Packed.exe", "wb");

	fwrite(pNewPE, 1, SumNewPESize, fp);

	fclose(fp);


}


//************************************
// 函数名称: Run
// 函数说明: 执行加壳代码的流程
// 函数参数: LPWSTR sourceFile
// 返 回 值: BOOL
// 创 建 人: Cray
// 创建日期: 2020/10/26
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

	printf("[*] 请输入要加壳程序:\n");
	_getws(FilePath);

	Run(FilePath);

	printf("[*] 加壳完成！已加壳程序保存在Packer.exe工作目录下！\n[*] 按任意键退出...");

	getchar();

	return 0;

}


