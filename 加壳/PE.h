#pragma once
#include <Windows.h>
class CPE
{
public:
	CPE();
	~CPE();
	void AnalyzePeHeader();
	void AnalyzeNewPeHeader();
	bool AddSection(char* szName, char* buf, DWORD dwSecSize, DWORD dwAttribute);//添加新区段
	bool AddRelocSection(char* pBuf);//添加重定位节
	DWORD AddSection1(char* szName, char * buf, DWORD dwSecSize, DWORD dwAttribute);
	void ChangeCharacteristic();

	DWORD GetTargetOep();//获得原始OEP，是个VA
	DWORD GetNewSectionRVA();//获得新区段RVA
	DWORD GetLastSectionRVA();//获取最后一个区段RVA
	void SetOep(DWORD dwNewOep);//设置新程序OEP
	void BaseRelocOff();//取消随机基址
	void EncodeDebug();//加密Debug程序
	DWORD GeTextSectionSize();//获得第一个区段大小
	DWORD GetTextSectionMemRVA();//是该节加载到内存后的首地址，
	bool SetSetionCharacteristics(DWORD Char, char * SetionName);//修改节的属性
	int My_strcmp(const char *src, const char * dest);//比较字符串函数
	bool InitializationAPI();
	DWORD GetGPAFunAddr();
	DWORD GetKernel32Base();
public:

	bool ReadFileToMem(TCHAR* pszPath);
	void SaveFile(TCHAR* NewPath);//保存文件
	DWORD CalcAlignment(DWORD dwSize, DWORD Align);
	DWORD GetIamgeBase();
	DWORD GetOldImageSize();
	bool SetAllSectionCharacteristic(DWORD Char);//设置所有区段属性


private://原始文件的信息
	char *m_pBuf;//原来的程序

	PIMAGE_DOS_HEADER m_pDos;
	PIMAGE_NT_HEADERS m_pNt;
	PIMAGE_SECTION_HEADER m_pFirstSection;
	DWORD m_dwSize;
	DWORD m_dwOldSizeOfImage;
private://添加区段后的信息
	DWORD m_dwNewSize;
	char* m_pNewBuf;
	PIMAGE_DOS_HEADER m_pNewDos;
	PIMAGE_NT_HEADERS m_pNewNt;
	PIMAGE_SECTION_HEADER m_pNewFirstSection;
};



// 基础API定义声明
typedef DWORD(WINAPI *LPGETPROCADDRESS)(HMODULE, LPCSTR);        // GetProcAddress
typedef HMODULE(WINAPI *LPLOADLIBRARYEX)(LPCTSTR, HANDLE, DWORD); // LoadLibaryEx
extern LPGETPROCADDRESS g_funGetProcAddress;
extern LPLOADLIBRARYEX  g_funLoadLibraryEx;

// 其他API定义声明
typedef VOID(WINAPI *LPEXITPROCESS)(UINT);                          // ExitProcess
typedef int (WINAPI *LPMESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, UINT);       // MessageBox
typedef HMODULE(WINAPI *LPGETMODULEHANDLE)(LPCWSTR);                // GetModuleHandle
typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect
extern LPEXITPROCESS     g_funExitProcess;
extern LPMESSAGEBOX      g_funMessageBox;
extern LPGETMODULEHANDLE g_funGetModuleHandle;
extern LPVIRTUALPROTECT  g_funVirtualProtect;
// 基础API定义声明
typedef DWORD(WINAPI *LPGETPROCADDRESS)(HMODULE, LPCSTR);        // GetProcAddress
typedef HMODULE(WINAPI *LPLOADLIBRARYEX)(LPCTSTR, HANDLE, DWORD); // LoadLibaryEx
extern LPGETPROCADDRESS g_funGetProcAddress;
extern LPLOADLIBRARYEX  g_funLoadLibraryEx;

// 其他API定义声明
typedef VOID(WINAPI *LPEXITPROCESS)(UINT);                          // ExitProcess
typedef int (WINAPI *LPMESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, UINT);       // MessageBox
typedef HMODULE(WINAPI *LPGETMODULEHANDLE)(LPCWSTR);                // GetModuleHandle
typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect
extern LPEXITPROCESS     g_funExitProcess;
extern LPMESSAGEBOX      g_funMessageBox;
extern LPGETMODULEHANDLE g_funGetModuleHandle;
extern LPVIRTUALPROTECT  g_funVirtualProtect;

