// 加壳.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "PE.h"
#include "../stub/stub.h"
#include <conio.h>
#define PATH _T("D:\\Hello_15PB.exe")
#define CHAR_TO_WCHAR(lpChar,lpW_Char)  MultiByteToWideChar(CP_ACP,NULL,lpChar,-1,lpW_Char,_countof(lpW_Char));
typedef struct _TYPEOFFSET
{
	WORD Offset : 12;
	WORD type : 4;
}TYPEOFFSET, *PTYPEOFFSET;

void Pack(TCHAR * Path)
{
	CPE obj;
	obj.ReadFileToMem(Path);
	//找到壳代码
	//hStub就是加载基址
	HMODULE hStub = LoadLibrary(_T("..//release//stub.dll"));//不用写内存，因为没对齐，没修复重定位
	
	//2 分析壳代码所在的PE文件，并填写相应的信息
	//2.1 找到PE信息
	char* pSubBuf = (char*)hStub;
	PIMAGE_DOS_HEADER pOldDos= (PIMAGE_DOS_HEADER)pSubBuf;
	PIMAGE_NT_HEADERS pOldNt = (PIMAGE_NT_HEADERS)(pOldDos->e_lfanew + pSubBuf);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pOldNt);

	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub, "g_PackInfo");

	DWORD difValue = (DWORD)pPackInfo - (DWORD)pSubBuf;

	//只能存到缓冲区里在修改，不能修改原来的内存
	//dll在内存中的大小
	DWORD ncount = pOldNt->OptionalHeader.SizeOfImage;
	//将dll复制一份进入缓冲区
	char *NewBuf = new char[ncount] {};
	memcpy(NewBuf, pSubBuf, ncount);
	//下面是缓冲区的PE信息
	PIMAGE_DOS_HEADER pBufDos = (PIMAGE_DOS_HEADER)NewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBufDos->e_lfanew + NewBuf);
	PIMAGE_SECTION_HEADER pBufFirstSection = IMAGE_FIRST_SECTION(pNt);
	//pSubBuf = NewBuf;

	PPACKINFO pBufPackInfo = 0;
	pBufPackInfo = PPACKINFO(difValue + NewBuf);

	DWORD TargetOep = obj.GetTargetOep();//获得目标程序的OEP，这里加过ImageBase

	

	pBufPackInfo->TargetOep = TargetOep;
	pBufPackInfo->dwReloc = obj.GetTextSectionMemRVA();//获取代码段RVA给dwReloc
	pBufPackInfo->dwSize = obj.GeTextSectionSize();


	//2.3先计算新的OEP//差值用的第一个区段，因为dll是Release版本编译，没有debug的在代码段之前那个区段
	DWORD tempValue = pPackInfo->dllOep - (DWORD)hStub - pFirstSection->VirtualAddress;
	DWORD NewOep = tempValue + obj.GetNewSectionRVA();
	//2.3修复重定位

	PIMAGE_DATA_DIRECTORY pRelocDir = pNt->OptionalHeader.DataDirectory + 5;
	PIMAGE_BASE_RELOCATION pReLoc = (PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress+NewBuf);

	while (pReLoc->SizeOfBlock!=0&& pReLoc->VirtualAddress!=0
		//pReLoc->VirtualAddress >= pFirstSection->VirtualAddress&&
		//pReLoc->VirtualAddress<pFirstSection->VirtualAddress + pFirstSection->Misc.VirtualSize
		)
	{
		char* BaseRelocAdd = pReLoc->VirtualAddress + NewBuf;
		DWORD dwCount = (pReLoc->SizeOfBlock - 8) / 2;
		PTYPEOFFSET pTypeOffset = PTYPEOFFSET(pReLoc + 1);
		for (DWORD i = 0;i < dwCount;i++) {
			if (pTypeOffset->type == 3) {
				DWORD* pReLoc = (DWORD*)(BaseRelocAdd + pTypeOffset->Offset);

				DWORD tempValue=*pReLoc-pNt->OptionalHeader.ImageBase - pFirstSection->VirtualAddress;//差值
				DWORD NewSectionVA = obj.GetNewSectionRVA() + obj.GetIamgeBase();
				*pReLoc = tempValue + NewSectionVA;
			}
			pTypeOffset++;//下一个重定位的单元
		}
		pReLoc = (PIMAGE_BASE_RELOCATION)((char *)pReLoc + pReLoc->SizeOfBlock);//下一块需要重定位的块
	}
	//2.4添加一个新的区段
	obj.AddSection((char*)"NewSect", 
		pBufFirstSection->VirtualAddress + NewBuf,
		pBufFirstSection->Misc.VirtualSize,
		pFirstSection->Characteristics);
	obj.EncodeDebug();

	//2.5设置目标程序的OEP到新区段中
	obj.SetOep(NewOep);

	//2.5.1添加重定位
	obj.AddRelocSection(NewBuf);
	obj.SetAllSectionCharacteristic(0xE0000020);
	//2.6 去掉随机基址
	//obj.BaseRelocOff();
	obj.SaveFile((TCHAR*)_T("D:\\newFile.exe"));
	delete[] NewBuf;
	FreeLibrary(hStub);
}




int main()
{
	HWND hwnd = GetConsoleWindow();
	ChangeWindowMessageFilterEx(hwnd,WM_DROPFILES, MSGFLT_ADD,NULL);
	ChangeWindowMessageFilterEx(hwnd,0x49, MSGFLT_ADD, NULL);
	
	TCHAR szBuf[MAX_PATH]{};
//	scanf_s("%S", szBuf, MAX_PATH);
//	printf("%S\n", szBuf);

	/*char szFileName[MAX_PATH]{};
	while (1)
	{
		if (_kbhit())
		{
			INPUT_RECORD e;
			DWORD d = 0;
			BOOL b = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &e, sizeof(INPUT_RECORD), &d);
			gets_s(szFileName);
			break;
		}
		Sleep(1);
	}
	system("cls");
	TCHAR tmp[MAX_PATH] = {};
	CHAR_TO_WCHAR(szFileName, tmp)*/
	Pack(L"D:\\222.exe"/*szBuf*/);
	return 0;
}
