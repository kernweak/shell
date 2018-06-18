#pragma once
#include <Windows.h>
class CPE
{
public:
	CPE();
	~CPE();
	void AnalyzePeHeader();
	void AnalyzeNewPeHeader();
	bool AddSection(char* szName, char* buf, DWORD dwSecSize, DWORD dwAttribute);//���������
	bool AddRelocSection(char* pBuf);//����ض�λ��
	DWORD AddSection1(char* szName, char * buf, DWORD dwSecSize, DWORD dwAttribute);
	void ChangeCharacteristic();

	DWORD GetTargetOep();//���ԭʼOEP���Ǹ�VA
	DWORD GetNewSectionRVA();//���������RVA
	DWORD GetLastSectionRVA();//��ȡ���һ������RVA
	void SetOep(DWORD dwNewOep);//�����³���OEP
	void BaseRelocOff();//ȡ�������ַ
	void EncodeDebug();//����Debug����
	DWORD GeTextSectionSize();//��õ�һ�����δ�С
	DWORD GetTextSectionMemRVA();//�Ǹýڼ��ص��ڴ����׵�ַ��
	bool SetSetionCharacteristics(DWORD Char, char * SetionName);//�޸Ľڵ�����
	int My_strcmp(const char *src, const char * dest);//�Ƚ��ַ�������
	bool InitializationAPI();
	DWORD GetGPAFunAddr();
	DWORD GetKernel32Base();
public:

	bool ReadFileToMem(TCHAR* pszPath);
	void SaveFile(TCHAR* NewPath);//�����ļ�
	DWORD CalcAlignment(DWORD dwSize, DWORD Align);
	DWORD GetIamgeBase();
	DWORD GetOldImageSize();
	bool SetAllSectionCharacteristic(DWORD Char);//����������������


private://ԭʼ�ļ�����Ϣ
	char *m_pBuf;//ԭ���ĳ���

	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pFirstSection;
	DWORD m_dwSize;
	DWORD m_dwOldSizeOfImage;
private://������κ����Ϣ
	DWORD m_dwNewSize;
	char* m_pNewBuf;
	PIMAGE_DOS_HEADER m_pNewDos;
	PIMAGE_NT_HEADERS m_pNewNt;
	PIMAGE_SECTION_HEADER m_pNewFirstSection;
};



// ����API��������
typedef DWORD(WINAPI *LPGETPROCADDRESS)(HMODULE, LPCSTR);        // GetProcAddress
typedef HMODULE(WINAPI *LPLOADLIBRARYEX)(LPCTSTR, HANDLE, DWORD); // LoadLibaryEx
extern LPGETPROCADDRESS g_funGetProcAddress;
extern LPLOADLIBRARYEX  g_funLoadLibraryEx;

// ����API��������
typedef VOID(WINAPI *LPEXITPROCESS)(UINT);                          // ExitProcess
typedef int (WINAPI *LPMESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, UINT);       // MessageBox
typedef HMODULE(WINAPI *LPGETMODULEHANDLE)(LPCWSTR);                // GetModuleHandle
typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect
extern LPEXITPROCESS     g_funExitProcess;
extern LPMESSAGEBOX      g_funMessageBox;
extern LPGETMODULEHANDLE g_funGetModuleHandle;
extern LPVIRTUALPROTECT  g_funVirtualProtect;
// ����API��������
typedef DWORD(WINAPI *LPGETPROCADDRESS)(HMODULE, LPCSTR);        // GetProcAddress
typedef HMODULE(WINAPI *LPLOADLIBRARYEX)(LPCTSTR, HANDLE, DWORD); // LoadLibaryEx
extern LPGETPROCADDRESS g_funGetProcAddress;
extern LPLOADLIBRARYEX  g_funLoadLibraryEx;

// ����API��������
typedef VOID(WINAPI *LPEXITPROCESS)(UINT);                          // ExitProcess
typedef int (WINAPI *LPMESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, UINT);       // MessageBox
typedef HMODULE(WINAPI *LPGETMODULEHANDLE)(LPCWSTR);                // GetModuleHandle
typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect
extern LPEXITPROCESS     g_funExitProcess;
extern LPMESSAGEBOX      g_funMessageBox;
extern LPGETMODULEHANDLE g_funGetModuleHandle;
extern LPVIRTUALPROTECT  g_funVirtualProtect;

