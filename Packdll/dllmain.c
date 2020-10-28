#include "header.h"

#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")


//************************************
// 函数名称: start
// 函数说明: 唯一的导出函数，从这开始
// 返 回 值: void
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
_declspec(dllexport) void start()
{
	Pestruct s_peinfo;

	PM_FUNC_TABLE pm_func_table;

	M_FUNC_TABLE m_func_table;

	DWORD kernel32Base = NULL;

	FARPROC OEP = NULL;

	m_func_table.mf_GetProcessAddress = 0;
	m_func_table.mf_LoadlibraryA = 0;
	m_func_table.mf_VirtualProtect = 0;
	m_func_table.mf_GetModuleHandleA = 0;
	m_func_table.mf_VirtualAlloc = 0;

	PCHAR pebase = Getbase();

	AntiDebug();

	s_peinfo = GetStruct(pebase);

	s_peinfo.mem_pe_base = pebase;


	kernel32Base = m_GetDllBaseFromFs(0xfad540f1);

	if (kernel32Base == NULL)
	{
		kernel32Base = m_GetDllBaseFromFs(0xb69e5f4);
	}

	pm_func_table = GetBaseApi(kernel32Base, m_func_table);

	s_peinfo.pm_func_table = pm_func_table;

	DecryptExc(s_peinfo);

	FixROC(s_peinfo);

	FixIAT(s_peinfo);

	OEP = (PCHAR)s_peinfo.mem_pe_base + s_peinfo.OEP;

	JmpToOep(OEP);

}

//************************************
// 函数名称: JmpToOep
// 函数说明: 执行原函数代码
// 函数参数: DWORD s_peinfo
// 创 建 人: Cray
// 创建日期: 2020/10/27
//************************************
_declspec(naked)
JmpToOep(DWORD s_peinfo)
{
	__asm
	{
		call eax;
		ret;
	}
}


DWORD HookIAT(DWORD lpfunc, PVOID pvirtualloc)
{

	M_VirtualAlloc mf_virtualloc = pvirtualloc;

	PBYTE pMyIAT = NULL;
	DWORD Value = 0;

	BYTE ss[] = {
		0x68, 0x00, 0x00, 0x00, 0x00,	       //PUSH Key
		0x58,								   //POP EAX
		0x35, 0x30, 0x6F, 0x70, 0x73,		   //XOR EAX,0x73796f30 
		0x75, 0x01,							   //JNE 01
		0x35,						           //混淆用
		0x50,						           //PUSH EAX
		0xC3 };						           //RET

	if (lpfunc & 0xF)
	{
		return lpfunc;
	}

	lpfunc = lpfunc ^ 0x73706F30;

	DWORD fun1 = lpfunc >> 24;
	DWORD fun2 = lpfunc >> 16 & 0xFF;
	DWORD fun3 = lpfunc >> 8 & 0xFF;
	DWORD fun4 = lpfunc & 0xFF;

	pMyIAT = mf_virtualloc(NULL, 0x30, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	ss[1] = fun4;
	ss[2] = fun3;
	ss[3] = fun2;
	ss[4] = fun1;

	for (int i = 0; i <= 16; i++)
	{
		pMyIAT[i] = ss[i];
	}


	return pMyIAT;
}


//************************************
// 函数名称: FixIAT
// 函数说明: 修复导入表
// 函数参数: Pestruct s_peinfo
// 返 回 值: BOOL
// 创 建 人: Cray
// 创建日期: 2020/10/27
//************************************
BOOL FixIAT(Pestruct  s_peinfo)
{
	BYTE ss[] = { 0x68,0x00,0x00,0x00,0x00,0xC3 };

	LPCSTR szDllname = NULL;
	PIMAGE_THUNK_DATA lpOrgNameArry = NULL;
	PIMAGE_THUNK_DATA lpFirNameArry = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByNameTable = NULL;
	HMODULE hMou;

	DWORD Funaddr;

	int i = 0;

	M_GetModuleHandleA m_GetModuleHandleA = s_peinfo.pm_func_table->mf_GetModuleHandleA;

	M_GetProcAddress m_GetProcAddress = s_peinfo.pm_func_table->mf_GetProcessAddress;

	M_LoadLibraryA m_LoadLibraryA = s_peinfo.pm_func_table->mf_LoadlibraryA;

	//M_VirtualAlloc m_virtualloc = s_peinfo.pm_func_table->mf_VirtualAlloc;
	FARPROC m_virtualloc = 0x4011111;


	PIMAGE_IMPORT_DESCRIPTOR pImportTalbe = (PCHAR)s_peinfo.mem_pe_base + s_peinfo.IAT.VirtualAddress;
	while (pImportTalbe->OriginalFirstThunk)
	{
		szDllname = (LPCSTR)((PCHAR)s_peinfo.mem_pe_base + pImportTalbe->Name);

		hMou = m_GetModuleHandleA(szDllname);

		if (hMou == NULL)
		{
			hMou = m_LoadLibraryA(szDllname);
			if (hMou == NULL)
			{
				//printf("[!]请将缺失的dll放置在搜索路径中...\n");
				return FALSE;
			}
		}
		//dll加载成功，开始导入需要的函数
		lpOrgNameArry = (PIMAGE_THUNK_DATA)((PCHAR)s_peinfo.mem_pe_base + pImportTalbe->OriginalFirstThunk);

		lpFirNameArry = (PIMAGE_THUNK_DATA)((PCHAR)s_peinfo.mem_pe_base + pImportTalbe->FirstThunk);

		i = 0;

		while (lpOrgNameArry[i].u1.AddressOfData)
		{
			lpImportByNameTable = (PIMAGE_IMPORT_BY_NAME)((PCHAR)s_peinfo.mem_pe_base + lpOrgNameArry[i].u1.AddressOfData);

			if (lpOrgNameArry[i].u1.Ordinal & 0x80000000 == 1)
			{
				//序号导入
				Funaddr = m_GetProcAddress(hMou, (LPSTR)(lpOrgNameArry[i].u1.Ordinal & 0xFFFF));
			}
			else
			{
				//名称导入
				Funaddr = m_GetProcAddress(hMou, lpImportByNameTable->Name);
			}

			//lpFirNameArry[i].u1.Function = (DWORD)Funaddr;
			lpFirNameArry[i].u1.Function = HookIAT(Funaddr, s_peinfo.pm_func_table->mf_VirtualAlloc);

			//DWORD fun1 = Funaddr >> 24;
			//DWORD fun2 = Funaddr >> 16 & 0xFF;
			//DWORD fun3 = Funaddr >> 8 & 0xFF;
			//DWORD fun4 = Funaddr & 0xFF;

			//PBYTE pMyIAT = m_virtualloc(NULL, 0x30, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			//ss[1] = fun4;
			//ss[2] = fun3;
			//ss[3] = fun2;
			//ss[4] = fun1;

			//for (int i = 0;i <= 5; i++)
			//{
			//	pMyIAT[i] = ss[i];
			//}

			//lpFirNameArry[i].u1.Function = pMyIAT;

			i++;
		}

		pImportTalbe++;
	}

	return TRUE;
}


//************************************
// 函数名称: FixROC
// 函数说明: 修复重定位信息
// 函数参数: Pestruct s_peinfo
// 返 回 值: BOOL
// 创 建 人: Cray
// 创建日期: 2020/10/27
//************************************
BOOL FixROC(Pestruct  s_peinfo)
{
	if (s_peinfo.ROC.VirtualAddress == NULL)
	{
		return TRUE;
	}
	DWORD tmpaddr = NULL;

	PIMAGE_BASE_RELOCATION pReloca = (PCHAR)s_peinfo.mem_pe_base + s_peinfo.ROC.VirtualAddress;

	PIMAGE_NT_HEADERS pNt = GetNTHeader(s_peinfo.mem_pe_base);

	while (pReloca->VirtualAddress != 0 && pReloca->SizeOfBlock != 0)
	{
		LPWORD pRelData = (LPWORD)((LPBYTE)pReloca + sizeof(IMAGE_BASE_RELOCATION));

		int nNumRel = (pReloca->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < nNumRel; i++)
		{
			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。

			if ((WORD)(pRelData[i] & 0xF000) == 0x3000) //这是一个需要修正的地址
			{
				//pReloca->VirtualAddress存的是页基质，(一个页4K，所以是0xFFF，刚好12位)
				LPDWORD pAddress = (LPDWORD)((PCHAR)s_peinfo.mem_pe_base + pReloca->VirtualAddress + (pRelData[i] & 0x0FFF));

				*pAddress = (PCHAR)s_peinfo.mem_pe_base - s_peinfo.oldImageBase + *pAddress;

			}

		}

		pReloca = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloca + pReloca->SizeOfBlock);
	}

	return TRUE;
}

//************************************
// 函数名称: GetBaseApi
// 函数说明: 获得三个重要函数，存到函数表中
// 函数参数: PVOID m_dwpPeBase
// 函数参数: M_FUNC_TABLE m_func_table
// 返 回 值: PM_FUNC_TABLE
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PM_FUNC_TABLE GetBaseApi(PVOID m_dwpPeBase, M_FUNC_TABLE m_func_table)
{

	PDWORD m_pfuncs_rva_table;

	DWORD m_export_ord;

	LPCSTR m_func_name;

	size_t hash;

	PIMAGE_EXPORT_DIRECTORY m_exportdir = m_GetImptable(m_dwpPeBase);

	PDWORD pfunc_name_rva = (PDWORD)((PBYTE)m_dwpPeBase + m_exportdir->AddressOfNames);

	PWORD pfunc_name_ord = (PWORD)((PBYTE)m_dwpPeBase + m_exportdir->AddressOfNameOrdinals);

	for (int i = 0; i < m_exportdir->NumberOfNames; i++)
	{

		m_func_name = (LPCSTR)((PBYTE)m_dwpPeBase + *(pfunc_name_rva + i));

		hash = m_GetHash(m_func_name, FALSE);

		m_export_ord = *(pfunc_name_ord + i);

		m_pfuncs_rva_table = (PDWORD)((PBYTE)m_dwpPeBase + m_exportdir->AddressOfFunctions);

		switch (hash)
		{
		case 0x392ab213:
			//GetProcAddress
			m_func_table.mf_GetProcessAddress = (PVOID)((PBYTE)m_dwpPeBase + *(m_pfuncs_rva_table + m_export_ord));
			break;

		case 0x635bbb86:
			//LoadLibraryA
			m_func_table.mf_LoadlibraryA = (PVOID)((PBYTE)m_dwpPeBase + *(m_pfuncs_rva_table + m_export_ord));
			break;

		case 0xc154bf76:
			//VirtualProtect
			m_func_table.mf_VirtualProtect = (PVOID)((PBYTE)m_dwpPeBase + *(m_pfuncs_rva_table + m_export_ord));
			break;

		case 0x46a3c91a:
			//GetModuleHandleA
			m_func_table.mf_GetModuleHandleA = (PVOID)((PBYTE)m_dwpPeBase + *(m_pfuncs_rva_table + m_export_ord));
			break;

		case 0x1f4ec089:
			//VirtualAlloc
			m_func_table.mf_VirtualAlloc = (PVOID)((PBYTE)m_dwpPeBase + *(m_pfuncs_rva_table + m_export_ord));
			break;

		default:
			break;
		}
	}

	return &m_func_table;
}


//************************************
// 函数名称: m_GetImptable
// 函数说明: 获取函数导出函数表
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_EXPORT_DIRECTORY
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_EXPORT_DIRECTORY m_GetImptable(PVOID m_dwpPeBase)
{

	PIMAGE_DATA_DIRECTORY m_datadir = GetNTHeader(m_dwpPeBase)->OptionalHeader.DataDirectory;

	PIMAGE_EXPORT_DIRECTORY m_exportdir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)m_dwpPeBase + m_datadir[0].VirtualAddress);

	return m_exportdir;
}


//************************************
// 函数名称: m_GetDllBaseFromFs
// 函数说明: 传入模块hash，从fs中拿到这个dll的基值
// 函数参数: size_t dllnamehash 
// 返 回 值: PVOID  要找的函数基值
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PVOID m_GetDllBaseFromFs(size_t dllnamehash)
{
	PM_LDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;

	PPEB pPeb = (PPEB)__readfsdword(0x30);

	PPEB_LDR_DATA pLdr = pPeb->Ldr;

	PLIST_ENTRY  pListEntryStart = pLdr->InMemoryOrderModuleList.Flink;

	PLIST_ENTRY  pListEntryEnd = pListEntryStart->Flink;

	PWSTR pdllname = NULL;

	DWORD dwapihash = 0;

	do
	{
		pLdrDataEntry = (PM_LDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryEnd, M_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		pdllname = pLdrDataEntry->DllName.Buffer;

		if (dllnamehash == m_GetHash((LPCSTR)pdllname, TRUE))
		{
			return pLdrDataEntry->DllBase;
		}

		pListEntryEnd = pListEntryEnd->Flink;

	} while (pListEntryStart != pListEntryEnd);

	return NULL;
}


//************************************
// 函数名称: EncryptExc
// 函数说明: 解密还原原始代码段
// 函数参数: Pestruct m_pestruct
// 返 回 值: VOID
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
VOID DecryptExc(Pestruct m_pestruct)
{
	DWORD start = 0;
	DWORD end = 0;
	PDWORD MemTextStart = 0;
	DWORD Encryptsize = 0;
	INT i = 0;

	DWORD encryptKey =
		GetNTHeader(m_pestruct.mem_pe_base)->FileHeader.TimeDateStamp;

	encryptKey = encryptKey ^ 0x12344321;

	DWORD entrypoint = m_pestruct.OEP;

	PIMAGE_SECTION_HEADER Psec = IMAGE_FIRST_SECTION(GetNTHeader(m_pestruct.mem_pe_base));

	INT SecNumber = GetNTHeader(m_pestruct.mem_pe_base)->FileHeader.NumberOfSections;

	M_VirtualProtect m_VirtualProtect = m_pestruct.pm_func_table->mf_VirtualProtect;

	DWORD pflOldProtect;

	for (; SecNumber > 0; SecNumber--)
	{
		start = Psec->VirtualAddress;
		end = Psec->VirtualAddress + Psec->SizeOfRawData;

		if (entrypoint >= start &
			entrypoint <= end)
		{
			Encryptsize = Psec->SizeOfRawData;

			MemTextStart =
				(PCHAR)(m_pestruct.mem_pe_base) + Psec->VirtualAddress;
			//break;
		}

		m_VirtualProtect((PCHAR)(m_pestruct.mem_pe_base) + Psec->VirtualAddress, Psec->SizeOfRawData, PAGE_EXECUTE_READWRITE, &pflOldProtect);
		Psec++;
	}


	for (i = 0; 4 * i < Encryptsize;i++)
	{

		if (*MemTextStart)
		{

			*MemTextStart = *MemTextStart ^ encryptKey;

			encryptKey = encryptKey << 25 | encryptKey >> 7;
		}

		MemTextStart++;

	}

	//这里把OEP也给修复了

	m_pestruct.OEP = (PCHAR)GetNTHeader(m_pestruct.mem_pe_base)->OptionalHeader.ImageBase + m_pestruct.OEP;

}


//************************************
// 函数名称: GetNTHeader
// 函数说明: 获取的NT头
// 函数参数: PVOID m_dwpPeBase
// 返 回 值: PIMAGE_NT_HEADERS
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PIMAGE_NT_HEADERS GetNTHeader(PVOID m_dwpPeBase)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_dwpPeBase;
	return (PIMAGE_NT_HEADERS)((PCHAR)m_dwpPeBase + pDos->e_lfanew);
}

//************************************
// 函数名称: GetStruct
// 函数说明: 获取DOS头中存储的原始PE信息
// 函数参数: PCHAR pebase
// 返 回 值: Pestruct 结构体
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
Pestruct GetStruct(PCHAR pebase)
{

	PPestruct newPestruct = (PPestruct)(pebase + 2);

	return *newPestruct;

}

//************************************
// 函数名称: Getbase
// 函数说明: 获取当前进程的基地址，当前程序已展开
// 返 回 值:  当前进程基值
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
PCHAR Getbase()
{
	PCHAR veip = 0;

	__asm
	{
		call next;
	next:
		pop veip;
	}

	while (TRUE)
	{
		//内存搜索最近的DOS头
		if ((*veip == 0x5A) & (*(veip - 1) == 0x4D))
		{
			DWORD e_lfanew = *(PDWORD)(veip + 0x3b);

			if ((*(veip - 1 + e_lfanew) == 0x50) & (*(veip + e_lfanew) == 0x45))
			{
				return veip - 1;
			}
		}

		veip--;
	}
}

//************************************
// 函数名称: AntiDebug
// 函数说明: 反逆向
// 返 回 值: DWORD
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
VOID AntiDebug()
{
	__asm
	{
		push ebp;
		pop eax;
		je next;
		mov ecx, 0x3571831;
		add eax, ecx;
		jne next;
		__emit 0xe9;
		ret;
	next:
		je last;
		jne last;
		__emit 0xe8;
	last:
		push 0x1024996;
		pop eax;
	}

}

//************************************
// 函数名称: m_GetHash
// 函数说明: 计算字符串hash
// 函数参数: const char * ApiName
// 函数参数: BOOL IsW  如果传入的是指向UNICODE的字符串 传入true，否者传入false
// 返 回 值: size_t hash(string)
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
size_t
m_GetHash(const char* ApiName, BOOL IsW)
{

	if (ApiName == NULL)
	{
		return 0;
	}
	DWORD dwhash = 0;


	if (IsW)
	{
		while (*(wchar_t*)ApiName != L'\0')
		{
			dwhash += *(wchar_t*)ApiName;

			dwhash = dwhash << 5 | dwhash >> 27;

			ApiName = ApiName + 2;

		}
	}
	else
	{
		while (*ApiName != '\0')
		{
			dwhash += *ApiName;

			dwhash = dwhash << 5 | dwhash >> 27;

			ApiName++;

		}
	}

	return dwhash;
}
