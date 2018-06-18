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
	//1 ������Ҫ����һ���µĿռ䣬�������������κ��PE�ļ�
	m_dwNewSize = m_dwSize + CalcAlignment(dwSecSize, 0x200);
	m_dwSize = m_dwNewSize;
	m_pNewBuf = nullptr;//
	m_pNewBuf = new char[m_dwNewSize];
	memset(m_pNewBuf, 0, m_dwNewSize);
	//��PE�ļ����������ڴ���,������PE�ؼ��ṹ��
	memcpy(m_pNewBuf, m_pBuf, m_dwNewSize);
	AnalyzeNewPeHeader();
	ChangeCharacteristic();
	//2 ��ʼ���������
	//2.1 �޸�ͷ����Ϣ�����������α�PEͷ�е�������������չͷ�е�SizeOfImage
	//2.1.1 �ҵ����α�����һ��
	PIMAGE_SECTION_HEADER pLastSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections;
	//2.1.2 ��ʼ������α���Ϣ
	strcpy_s((char *)pNewSection->Name, 8, szName);//������
	pNewSection->Characteristics = dwAttribute;//��������
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
	//2.2 �����PE�ļ��ĺ������һ��������
	memcpy(m_pNewBuf + pNewSection->PointerToRawData, buf, dwSecSize);
	delete[] m_pBuf;
	m_pBuf = m_pNewBuf;
	return true;

}

bool CPE::AddRelocSection(char * pBuf)
{
	//��λ�ض�λ��
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
	//���ض�λ��Ϣ��ӵ���PE�ļ�����󣬷��ظ����ε�RVA
	DWORD dwStubRelocRva = AddSection1(".sreloc", dwRelocRva + pBuf, dwRelocSize, dwSectionAttribute);
	//����PE�ļ����ض�λ��ָ��stub�ض�λ����
	PIMAGE_DOS_HEADER pReDos = (PIMAGE_DOS_HEADER)m_pNewBuf;
	PIMAGE_NT_HEADERS pReNt = (PIMAGE_NT_HEADERS)(pReDos->e_lfanew + m_pNewBuf);
	pReNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = dwStubRelocRva;
	pReNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = dwRelocSize;
	return TRUE;
}

DWORD CPE::AddSection1(char * szName, char * buf, DWORD dwSecSize, DWORD dwAttribute)
{

	//1 ������Ҫ����һ���µĿռ䣬�������������κ��PE�ļ�
	m_dwNewSize = m_dwSize + CalcAlignment(dwSecSize, 0x200);
	m_dwSize = m_dwNewSize;
	m_pNewBuf = nullptr;//�ÿգ���ֹ�ظ�����ռ�
	m_pNewBuf = new char[m_dwNewSize];
	//��ȫ����Ϊ0
	memset(m_pNewBuf, 0, m_dwNewSize);
	//��PE�ļ����������ڴ���,������PE�ؼ��ṹ��
	memcpy(m_pNewBuf, m_pBuf, m_dwNewSize);
	AnalyzeNewPeHeader();
	//2 ��ʼ���������
	//2.1 �޸�ͷ����Ϣ�����������α�PEͷ�е�������������չͷ�е�SizeOfImage
	//2.1.1 �ҵ����α�����һ��
	PIMAGE_SECTION_HEADER pLastSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections - 1;
	PIMAGE_SECTION_HEADER pNewSection =
		m_pNewFirstSection + m_pNewNt->FileHeader.NumberOfSections;
	//2.1.2 ��ʼ������α���Ϣ
	strcpy_s((char *)pNewSection->Name, 8, szName);//������
	pNewSection->Characteristics = dwAttribute;//��������
											   //�ļ�ƫ��
	pNewSection->PointerToRawData = pLastSection->PointerToRawData +
		pLastSection->SizeOfRawData;
	//�ļ��еĽڴ�С 0x200����
	pNewSection->SizeOfRawData = CalcAlignment(dwSecSize, 0x200);
	//�ڴ��е�RVA
	pNewSection->VirtualAddress = pLastSection->VirtualAddress +
		CalcAlignment(pLastSection->Misc.VirtualSize, 0x1000);
	//���ڴ��еĴ�С
	pNewSection->Misc.VirtualSize = dwSecSize;
	//�ļ�ͷ�нڵ�����++
	m_pNewNt->FileHeader.NumberOfSections++;
	//�ļ�ͷ�еľ����С�ֶ�
	m_pNewNt->OptionalHeader.SizeOfImage =
		CalcAlignment(m_pNewNt->OptionalHeader.SizeOfImage, 0x1000) +
		CalcAlignment(dwSecSize, 0x200);
	//2.2 �����PE�ļ��ĺ������һ��������
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
	int result = 0;          //������ʱ�������ڱ��淵�ؽ��
	__asm                       //������࿪ʼ
	{
		mov esi, src;//��Դ�ַ�������ds:esi
		mov edi, dest;//��Ŀ���ַ�������es:edi
	START://��ʼ
		lodsb;//��ds:esi�ĵ�һ���ֽ�װ��Ĵ���AL��ͬʱ[esi]+1
		scasb;//��es:edi�ĵ�һ���ֽں�AL�����ͬʱ[edi]+1
			  //cmpsb ��edi �� esi���ֽ����
		jne NOTEQ;     //����ȣ�ת��NOTEQ����

		test al, al         //����AL�Ƿ�ΪNULL
			jne START       //��Ϊ�գ���Ƚ���һ��
			xor eax, eax     //Ϊ��,���Ĵ���EAX���Ϊ0
			jmp ENDCMP      //��ת�����ؽ���ĵط�
			NOTEQ :                           //�����
		mov eax, 1     //�����ʱ�Ĵ���,��EAX��1
			jg ENDCMP     //����Ǵ��ڵĻ�,�������ؽ���ĵط�
			neg eax            //��EAXȡ��,��Ϊ-1

			ENDCMP : mov result, eax     //�������result

	}

	return result;              //����

}


bool CPE::ReadFileToMem(TCHAR * pszPath)
{
	//1 ���ļ�
	HANDLE hFile = CreateFile(pszPath,FILE_ALL_ACCESS,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		NULL);
	//2 ��ȡ�ļ�
	DWORD dwRealSize = 0;
	m_dwSize = GetFileSize(hFile, NULL);
	m_pBuf = new char[m_dwSize];
	memset(m_pBuf, 0, m_dwSize);
	ReadFile(hFile, m_pBuf, m_dwSize, &dwRealSize, NULL);
	//3 ����PE�ļ�
	AnalyzePeHeader();
	CloseHandle(hFile);
	return true;

}

void CPE::SaveFile(TCHAR * NewPath)
{
	//1.���ļ�
	HANDLE hFile = CreateFile(NewPath, FILE_ALL_ACCESS, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//2.д���ļ�
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
		mov eax, dword ptr fs : [0x30] // eax = PEB�ĵ�ַ
		mov eax, [eax + 0x0C]          // eax = ָ��PEB_LDR_DATA�ṹ��ָ��
		mov eax, [eax + 0x1C]          // eax = ģ���ʼ�������ͷָ��InInitializationOrderModuleList
		mov eax, [eax]               // eax = �б��еĵڶ�����Ŀ
		mov eax, [eax + 0x08]          // eax = ��ȡ����Kernel32.dll��ַ��Win7�»�ȡ����KernelBase.dll�Ļ�ַ��
		mov dwKernel32Addr, eax
		pop eax
	}

	return dwKernel32Addr;
}

DWORD CPE::GetGPAFunAddr()
{
	DWORD dwAddrBase = GetKernel32Base();

	// 1. ��ȡDOSͷ��NTͷ
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)dwAddrBase;
	pNt_Header = (PIMAGE_NT_HEADERS)(dwAddrBase + pDos_Header->e_lfanew);

	// 2. ��ȡ��������
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory;
	pDataDir = &pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);

	// 3����ȡ������ı�Ҫ��Ϣ
	DWORD dwModOffset = pExport->Name;                                  // ģ�������
	DWORD dwFunCount = pExport->NumberOfFunctions;                      // ��������������
	DWORD dwNameCount = pExport->NumberOfNames;                         // �������Ƶ�����

	PDWORD pEAT = (PDWORD)(dwAddrBase + pExport->AddressOfFunctions);   // ��ȡ��ַ���RVA
	PDWORD pENT = (PDWORD)(dwAddrBase + pExport->AddressOfNames);       // ��ȡ���Ʊ��RVA
	PWORD pEIT = (PWORD)(dwAddrBase + pExport->AddressOfNameOrdinals);  //��ȡ�������RVA

																		// 4����ȡGetProAddress�����ĵ�ַ
	for (DWORD i = 0; i < dwFunCount; i++)
	{
		if (!pEAT[i])
		{
			continue;
		}

		// 4.1 ��ȡ���
		DWORD dwID = pExport->Base + i;

		// 4.2 ����EIT ���л�ȡ�� GetProcAddress�ĵ�ַ
		for (DWORD dwIdx = 0; dwIdx < dwNameCount; dwIdx++)
		{
			// ��ű��е�Ԫ�ص�ֵ ��Ӧ�ź�����ַ���λ��
			if (pEIT[dwIdx] == i)
			{
				//������Ż�ȡ�����Ʊ��е�����
				DWORD dwNameOffset = pENT[dwIdx];
				char * pFunName = (char*)(dwAddrBase + dwNameOffset);

				//�ж��Ƿ���GetProcAddress����
				if (!strcmp(pFunName, "GetProcAddress"))
				{
					// ��ȡEAT�ĵ�ַ ����GetProcAddress��ַ����
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

	// 1. ��ʼ������API ����ʹ�õ���LoadLibraryExW
	g_funGetProcAddress = (LPGETPROCADDRESS)GetGPAFunAddr();
	g_funLoadLibraryEx = (LPLOADLIBRARYEX)g_funGetProcAddress((HMODULE)GetKernel32Base(), "LoadLibraryExW");

	// 2. ��ʼ������API
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

