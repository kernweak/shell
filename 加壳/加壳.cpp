// �ӿ�.cpp : �������̨Ӧ�ó������ڵ㡣
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
	//�ҵ��Ǵ���
	//hStub���Ǽ��ػ�ַ
	HMODULE hStub = LoadLibrary(_T("..//release//stub.dll"));//����д�ڴ棬��Ϊû���룬û�޸��ض�λ
	
	//2 �����Ǵ������ڵ�PE�ļ�������д��Ӧ����Ϣ
	//2.1 �ҵ�PE��Ϣ
	char* pSubBuf = (char*)hStub;
	PIMAGE_DOS_HEADER pOldDos= (PIMAGE_DOS_HEADER)pSubBuf;
	PIMAGE_NT_HEADERS pOldNt = (PIMAGE_NT_HEADERS)(pOldDos->e_lfanew + pSubBuf);
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pOldNt);

	PPACKINFO pPackInfo = (PPACKINFO)GetProcAddress(hStub, "g_PackInfo");

	DWORD difValue = (DWORD)pPackInfo - (DWORD)pSubBuf;

	//ֻ�ܴ浽�����������޸ģ������޸�ԭ�����ڴ�
	//dll���ڴ��еĴ�С
	DWORD ncount = pOldNt->OptionalHeader.SizeOfImage;
	//��dll����һ�ݽ��뻺����
	char *NewBuf = new char[ncount] {};
	memcpy(NewBuf, pSubBuf, ncount);
	//�����ǻ�������PE��Ϣ
	PIMAGE_DOS_HEADER pBufDos = (PIMAGE_DOS_HEADER)NewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBufDos->e_lfanew + NewBuf);
	PIMAGE_SECTION_HEADER pBufFirstSection = IMAGE_FIRST_SECTION(pNt);
	//pSubBuf = NewBuf;

	PPACKINFO pBufPackInfo = 0;
	pBufPackInfo = PPACKINFO(difValue + NewBuf);

	DWORD TargetOep = obj.GetTargetOep();//���Ŀ������OEP������ӹ�ImageBase

	

	pBufPackInfo->TargetOep = TargetOep;
	pBufPackInfo->dwReloc = obj.GetTextSectionMemRVA();//��ȡ�����RVA��dwReloc
	pBufPackInfo->dwSize = obj.GeTextSectionSize();


	//2.3�ȼ����µ�OEP//��ֵ�õĵ�һ�����Σ���Ϊdll��Release�汾���룬û��debug���ڴ����֮ǰ�Ǹ�����
	DWORD tempValue = pPackInfo->dllOep - (DWORD)hStub - pFirstSection->VirtualAddress;
	DWORD NewOep = tempValue + obj.GetNewSectionRVA();
	//2.3�޸��ض�λ

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

				DWORD tempValue=*pReLoc-pNt->OptionalHeader.ImageBase - pFirstSection->VirtualAddress;//��ֵ
				DWORD NewSectionVA = obj.GetNewSectionRVA() + obj.GetIamgeBase();
				*pReLoc = tempValue + NewSectionVA;
			}
			pTypeOffset++;//��һ���ض�λ�ĵ�Ԫ
		}
		pReLoc = (PIMAGE_BASE_RELOCATION)((char *)pReLoc + pReLoc->SizeOfBlock);//��һ����Ҫ�ض�λ�Ŀ�
	}
	//2.4���һ���µ�����
	obj.AddSection((char*)"NewSect", 
		pBufFirstSection->VirtualAddress + NewBuf,
		pBufFirstSection->Misc.VirtualSize,
		pFirstSection->Characteristics);
	obj.EncodeDebug();

	//2.5����Ŀ������OEP����������
	obj.SetOep(NewOep);

	//2.5.1����ض�λ
	obj.AddRelocSection(NewBuf);
	obj.SetAllSectionCharacteristic(0xE0000020);
	//2.6 ȥ�������ַ
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
