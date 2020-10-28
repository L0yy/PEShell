#include <stdio.h>
#include <windows.h>

//************************************
// ��������: m_GetHash
// ����˵��: �����ַ���hash
// ��������: const char * ApiName
// ��������: BOOL IsW  ����������ָ��UNICODE���ַ��� ����true�����ߴ���false
// �� �� ֵ: DWORD hash(string)
// �� �� ��: Cray
// ��������: 2020/10/26
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