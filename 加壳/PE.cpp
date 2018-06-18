#include "stdafx.h"
#include "PE.h"
#include<iostream>
#include<string>
using namespace std;
LPGETPROCADDRESS  g_funGetProcAddress = nullptr;
LPLOADLIBRARYEX   g_funLoadLibraryEx = nullptr;
LPEXITPROCESS     g_funExitProcess = nullptr;
LPMESSAGEBOX      g_funMessageBox = nullptr;
LPGETMODULEHANDLE g_funGetModuleHandle = nullptr;
LPVIRTUALPROTECT  g_funVirtualProtect = nullptr;



CPE::CPE()
{
}


CPE::~CPE()
{
}

void CPE::AnalyzePeHeader()
{
	m_pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	m_pNt = (PIMAGE_NT_HEADERS)(m_pDos->e_lfanew + m_pBuf);
	m_pFirstSection = IMAGE_FIRST_SECTION(m_pNt);
	m_dwOldSizeOfImage = m_pNt->OptionalHeader.SizeOfImage;
}

void CPE::AnalyzeNewPeHeader()
{
	m_pNewDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	m_pNewNt = (PIMAGE_NT_HEADERS)(m_pNewDos->e_lfanew + m_pNewBuf);
	m_pNewFirstSection = IMAGE_FIRST_SECTION(m_pNewNt);
}

bool CPE::AddSection(char * szName, char * buf, DWORD dwSecSize, DWORD dwAttribute)
{
	//1 我们需要申请一块新的空间，用来存放添加区段后的PE文件
	m_dwNewSize = m_dwSize + CalcAlignment(dwSecSize, 0x200);
	m_dwSize = m_dwNewSize;
	m_pNewBuf = nullptr;//
	m_pNewBuf = new char[m_dwNewSize];
	memset(m_pNewBuf, 0, m_dwNewSize);
	//将PE文件拷贝到新内存中,并分析PE关键结构体
	memcpy(m_pNewBuf, m_pBuf, m_dwNewSize);
	AnalyzeNewPeHeader();
	ChangeCharacteristic();
	//2 开始添加新区段
	//2.1 修改头部信息，包括：区段表，PE头中的区段数量，扩展头中的SizeOfImage
	//2.1.1 找到区段表的最后一项
	PIMAGE_SECTION_HEADER pLastSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections;
	//2.1.2 开始填充区段表信息
	strcpy_s((char *)pNewSection->Name, 8, szName);//区段名
	pNewSection->Characteristics = dwAttribute;//区段属性
	pNewSection->PointerToRawData = pLastSection->PointerToRawData +
		pLastSection->SizeOfRawData;
	pNewSection->SizeOfRawData = CalcAlignment(dwSecSize, 0x200);
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);

	pNewSection->Misc.VirtualSize = dwSecSize;

	m_pNewNt->FileHeader.NumberOfSections++;
	m_pNewNt->OptionalHeader.SizeOfImage =
		CalcAlignment(m_pNewNt->OptionalHeader.SizeOfImage, 0x1000) +
		CalcAlignment(dwSecSize, 0x1000);
	//2.2 真的在PE文件的后面添加一个新区段
	memcpy(m_pNewBuf + pNewSection->PointerToRawData, buf, dwSecSize);
	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;
	return true;

}

bool CPE::AddRelocSection(char * pBuf)
{
	//定位重定位块
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_DATA_DIRECTORY pRelocDir = (&pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pRelocDir->VirtualAddress + pBuf);

	DWORD dwOldRelocRva = 0;
	DWORD dwNewRelocRva = CalcAlignment(GetOldImageSize(), 0x1000);
	while (pReloc->VirtualAddress)
	{
		dwOldRelocRva = pReloc->VirtualAddress - dwOldRelocRva;
		pReloc->VirtualAddress = dwNewRelocRva;
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
		if (pReloc->VirtualAddress) {
	dwNewRelocRva += (pReloc->VirtualAddress - dwOldRelocRva);
	printf("%d",10);
	}
		}
			
	DWORD dwRelocRva = 0;
	DWORD dwRelocSize = 0;
	DWORD dwSectionAttribute = 0;

	for (;;)
	{
		if (!My_strcmp((char*)pSection->Name, ".reloc"))
		{
			dwRelocRva = pSection->VirtualAddress;
			dwRelocSize = pSection->SizeOfRawData;
			dwSectionAttribute = pSection->Characteristics;
			break;
		}
		pSection++;
	}
	//将重定位信息添加到新PE文件的最后，返回该区段的RVA
	DWORD dwStubRelocRva = AddSection1(".sreloc", dwRelocRva + pBuf, dwRelocSize, dwSectionAttribute);
	//将新PE文件的重定位表指向stub重定位区段
	PIMAGE_DOS_HEADER pReDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pReNt = (PIMAGE_NT_HEADERS)(pReDos->e_lfanew + m_pNewBuf);
	pReNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwStubRelocRva;
	pReNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwRelocSize;
	return TRUE;
}

DWORD CPE::AddSection1(char * szName, char * buf, DWORD dwSecSize, DWORD dwAttribute)
{

	//1 我们需要申请一块新的空间，用来存放添加区段后的PE文件
	m_dwNewSize = m_dwSize + CalcAlignment(dwSecSize, 0x200);
	m_dwSize = m_dwNewSize;
	m_pNewBuf = nullptr;//置空，防止重复申请空间
	m_pNewBuf = new char[m_dwNewSize];
	//先全部至为0
	memset(m_pNewBuf, 0, m_dwNewSize);
	//将PE文件拷贝到新内存中,并分析PE关键结构体
	memcpy(m_pNewBuf, m_pBuf, m_dwNewSize);
	AnalyzeNewPeHeader();
	//2 开始添加新区段
	//2.1 修改头部信息，包括：区段表，PE头中的区段数量，扩展头中的SizeOfImage
	//2.1.1 找到区段表的最后一项
	PIMAGE_SECTION_HEADER pLastSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections;
	//2.1.2 开始填充区段表信息
	strcpy_s((char *)pNewSection->Name, 8, szName);//区段名
	pNewSection->Characteristics = dwAttribute;//区段属性
											   //文件偏移
	pNewSection->PointerToRawData = pLastSection->PointerToRawData +
		pLastSection->SizeOfRawData;
	//文件中的节大小 0x200对齐
	pNewSection->SizeOfRawData = CalcAlignment(dwSecSize, 0x200);
	//内存中的RVA
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
	//在内存中的大小
	pNewSection->Misc.VirtualSize = dwSecSize;
	//文件头中节的数量++
	m_pNewNt->FileHeader.NumberOfSections++;
	//文件头中的镜像大小字段
	m_pNewNt->OptionalHeader.SizeOfImage =
		CalcAlignment(m_pNewNt->OptionalHeader.SizeOfImage, 0x1000) +
		CalcAlignment(dwSecSize, 0x200);
	//2.2 真的在PE文件的后面添加一个新区段
	memcpy(m_pNewBuf + pNewSection->PointerToRawData, buf, dwSecSize);
	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;
	return pNewSection->VirtualAddress;
}

void CPE::ChangeCharacteristic()
{
	PIMAGE_SECTION_HEADER temSection = m_pNewFirstSection + 1;
	temSection->Characteristics |= IMAGE_SCN_MEM_WRITE;

}

DWORD CPE::GetTargetOep()
{
	return m_pNt->OptionalHeader.AddressOfEntryPoint;
	//return m_pNt->OptionalHeader.AddressOfEntryPoint + m_pNt->OptionalHeader.ImageBase;
}

DWORD CPE::GetNewSectionRVA()
{
	PIMAGE_SECTION_HEADER pLastSection = m_pFirstSection + m_pNt->FileHeader.NumberOfSections - 1;
	return pLastSection->VirtualAddress + CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
}

DWORD CPE::GetLastSectionRVA()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pNewBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pLastSection = pSection + pNt->FileHeader.NumberOfSections - 1;

	return (DWORD)pLastSection;
}

void CPE::SetOep(DWORD dwNewOep)
{
	m_pNewNt->OptionalHeader.AddressOfEntryPoint = dwNewOep;
}

void CPE::BaseRelocOff()
{
	m_pNewNt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

void CPE::EncodeDebug()
{
	PIMAGE_SECTION_HEADER pSecondSection = m_pNewFirstSection + 1;
	unsigned char* pBuf = pSecondSection->PointerToRawData + (unsigned char *)m_pNewBuf;
	for (int i = 0;i < pSecondSection->SizeOfRawData;i++) {
		pBuf[i] ^= 0x15;
	}
}

DWORD CPE::GeTextSectionSize()
{
	PIMAGE_SECTION_HEADER pTextSection = m_pFirstSection;
	for (;;)
	{
		if (strcmp((char*)pTextSection->Name, ".text") == 0)
		{
			break;
		}
		pTextSection++;
	}
	return pTextSection->SizeOfRawData;
}

DWORD CPE::GetTextSectionMemRVA()
{
	PIMAGE_SECTION_HEADER pTextSection = m_pFirstSection;
	for (;;)
	{
		if (strcmp((char*)pTextSection->Name, ".text") == 0)
		{
			break;
		}
		pTextSection++;
	}
	return pTextSection->VirtualAddress;
}

bool CPE::SetSetionCharacteristics(DWORD Char, char * SetionName)
{
	PIMAGE_SECTION_HEADER pBufFirstSection = IMAGE_FIRST_SECTION(m_pNewNt);
	while (pBufFirstSection->Name)
	{
		char* ch = (char*)pBufFirstSection->Name;
		if (My_strcmp(ch, SetionName) == 0) {
			pBufFirstSection->Characteristics = Char;
			return true;
		}
		pBufFirstSection++;
	}
	return false;
}

int CPE::My_strcmp(const char * src, const char * dest)

{
	int result = 0;          //定义临时变量用于保存返回结果
	__asm                       //内联汇编开始
	{
		mov esi, src;//将源字符串放入ds:esi
		mov edi, dest;//将目标字符串放入es:edi
	START://开始
		lodsb;//将ds:esi的第一个字节装入寄存器AL，同时[esi]+1
		scasb;//将es:edi的第一个字节和AL相减，同时[edi]+1
			  //cmpsb 将edi 和 esi的字节相减
		jne NOTEQ;     //不相等，转到NOTEQ处理

		test al, al         //看看AL是否为NULL
			jne START       //不为空，则比较下一个
			xor eax, eax     //为空,将寄存器EAX清空为0
			jmp ENDCMP      //跳转到返回结果的地方
			NOTEQ :                           //不相等
		mov eax, 1     //不相等时的处理,将EAX置1
			jg ENDCMP     //如果是大于的话,跳到返回结果的地方
			neg eax            //将EAX取反,变为-1

			ENDCMP : mov result, eax     //结果存入result

	}

	return result;              //返回

}


bool CPE::ReadFileToMem(TCHAR * pszPath)
{
	//1 打开文件
	HANDLE hFile = CreateFile(pszPath,FILE_ALL_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		NULL);
	//2 读取文件
	DWORD dwRealSize = 0;
	m_dwSize = GetFileSize(hFile, NULL);
	m_pBuf = new char[m_dwSize];
	memset(m_pBuf, 0, m_dwSize);
	ReadFile(hFile, m_pBuf, m_dwSize, &dwRealSize, NULL);
	//3 解析PE文件
	AnalyzePeHeader();
	CloseHandle(hFile);
	return true;

}

void CPE::SaveFile(TCHAR * NewPath)
{
	//1.打开文件
	HANDLE hFile = CreateFile(NewPath, FILE_ALL_ACCESS, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.写入文件
	DWORD dwRealSize = 0;
	WriteFile(hFile, m_pNewBuf, m_dwNewSize, &dwRealSize, NULL);
}

DWORD CPE::CalcAlignment(DWORD dwSize, DWORD Align)
{
	if (dwSize%Align == 0)
	{
		return dwSize;
	}
	else
	{
		return (dwSize / Align + 1)*Align;
	}

}

DWORD CPE::GetIamgeBase()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)m_pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + m_pBuf);
	return pNt->OptionalHeader.ImageBase;
	return 0;
}

DWORD CPE::GetOldImageSize()
{
	return m_dwOldSizeOfImage;
}

bool CPE::SetAllSectionCharacteristic(DWORD Char)
{
	PIMAGE_SECTION_HEADER pBufFirstSection = IMAGE_FIRST_SECTION(m_pNewNt);
	int i = m_pNewNt->FileHeader.NumberOfSections;
	while (i--)
	{
		pBufFirstSection->Characteristics = Char;
		pBufFirstSection++;
	}
	return false;
}

DWORD CPE::GetKernel32Base()
{
	DWORD dwKernel32Addr = 0;
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30] // eax = PEB的地址
		mov eax, [eax + 0x0C]          // eax = 指向PEB_LDR_DATA结构的指针
		mov eax, [eax + 0x1C]          // eax = 模块初始化链表的头指针InInitializationOrderModuleList
		mov eax, [eax]               // eax = 列表中的第二个条目
		mov eax, [eax + 0x08]          // eax = 获取到的Kernel32.dll基址（Win7下获取的是KernelBase.dll的基址）
		mov dwKernel32Addr, eax
		pop eax
	}

	return dwKernel32Addr;
}

DWORD CPE::GetGPAFunAddr()
{
	DWORD dwAddrBase = GetKernel32Base();

	// 1. 获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)dwAddrBase;
	pNt_Header = (PIMAGE_NT_HEADERS)(dwAddrBase + pDos_Header->e_lfanew);

	// 2. 获取导出表项
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory;
	pDataDir = &pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);

	// 3、获取导出表的必要信息
	DWORD dwModOffset = pExport->Name;                                  // 模块的名称
	DWORD dwFunCount = pExport->NumberOfFunctions;                      // 导出函数的数量
	DWORD dwNameCount = pExport->NumberOfNames;                         // 导出名称的数量

	PDWORD pEAT = (PDWORD)(dwAddrBase + pExport->AddressOfFunctions);   // 获取地址表的RVA
	PDWORD pENT = (PDWORD)(dwAddrBase + pExport->AddressOfNames);       // 获取名称表的RVA
	PWORD pEIT = (PWORD)(dwAddrBase + pExport->AddressOfNameOrdinals);  //获取索引表的RVA

																		// 4、获取GetProAddress函数的地址
	for (DWORD i = 0; i < dwFunCount; i++)
	{
		if (!pEAT[i])
		{
			continue;
		}

		// 4.1 获取序号
		DWORD dwID = pExport->Base + i;

		// 4.2 变量EIT 从中获取到 GetProcAddress的地址
		for (DWORD dwIdx = 0; dwIdx < dwNameCount; dwIdx++)
		{
			// 序号表中的元素的值 对应着函数地址表的位置
			if (pEIT[dwIdx] == i)
			{
				//根据序号获取到名称表中的名字
				DWORD dwNameOffset = pENT[dwIdx];
				char * pFunName = (char*)(dwAddrBase + dwNameOffset);

				//判断是否是GetProcAddress函数
				if (!strcmp(pFunName, "GetProcAddress"))
				{
					// 获取EAT的地址 并将GetProcAddress地址返回
					DWORD dwFunAddrOffset = pEAT[i];
					return dwAddrBase + dwFunAddrOffset;
				}
			}
		}
	}
	return -1;
}

bool CPE::InitializationAPI()
{
	HMODULE hModule;

	// 1. 初始化基础API 这里使用的是LoadLibraryExW
	g_funGetProcAddress = (LPGETPROCADDRESS)GetGPAFunAddr();
	g_funLoadLibraryEx = (LPLOADLIBRARYEX)g_funGetProcAddress((HMODULE)GetKernel32Base(), "LoadLibraryExW");

	// 2. 初始化其他API
	hModule = NULL;
	if (!(hModule = g_funLoadLibraryEx(L"kernel32.dll", NULL, NULL)))  return false;
	g_funExitProcess = (LPEXITPROCESS)g_funGetProcAddress(hModule, "ExitProcess");
	hModule = NULL;
	if (!(hModule = g_funLoadLibraryEx(L"user32.dll", NULL, NULL)))  return false;
	g_funMessageBox = (LPMESSAGEBOX)g_funGetProcAddress(hModule, "MessageBoxW");
	hModule = NULL;
	if (!(hModule = g_funLoadLibraryEx(L"kernel32.dll", NULL, NULL)))  return false;
	g_funGetModuleHandle = (LPGETMODULEHANDLE)g_funGetProcAddress(hModule, "GetModuleHandleW");
	hModule = NULL;
	if (!(hModule = g_funLoadLibraryEx(L"kernel32.dll", NULL, NULL)))  return false;
	g_funVirtualProtect = (LPVIRTUALPROTECT)g_funGetProcAddress(hModule, "VirtualProtect");

	return true;
}

