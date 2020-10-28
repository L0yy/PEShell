#include <stdio.h>
#include <windows.h>

//************************************
// 函数名称: m_GetHash
// 函数说明: 计算字符串hash
// 函数参数: const char * ApiName
// 函数参数: BOOL IsW  如果传入的是指向UNICODE的字符串 传入true，否者传入false
// 返 回 值: DWORD hash(string)
// 创 建 人: Cray
// 创建日期: 2020/10/26
//************************************
DWORD m_GetHash(const char* ApiName, BOOL IsW)
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


int main()
{
	DWORD hash = m_GetHash("kernel32.dll", FALSE);

	printf("0x%x\n", hash);

	getchar();
}