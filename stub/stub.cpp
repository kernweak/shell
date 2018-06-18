// stub.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "stub.h"
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
typedef DWORD(WINAPI* FPGetProcAddress)(HMODULE, LPCSTR);//GetProcAddress
typedef HMODULE(WINAPI* FPLoadLibraryExW)(LPCTSTR, HANDLE, DWORD); // LoadLibaryEx
typedef int (WINAPI* FPMessageBoxW)(HWND, LPCTSTR, LPCTSTR, UINT);//MessageBoxW
typedef HMODULE(WINAPI *FPGetModuleHandleW)(_In_opt_ LPCTSTR lpModuleName);//GetModuleHandle
typedef ATOM(WINAPI* FPRegisterClassW)(_In_ const WNDCLASS *lpWndClass);//FPRegisterClassW
typedef HWND(WINAPI *FPCreateWindowExW)(_In_ DWORD dwExStyle,_In_opt_ LPCTSTR lpClassName,_In_opt_ LPCTSTR lpWindowName,\
	_In_ DWORD dwStyle,_In_ int x,_In_ int y,_In_ int nWidth,_In_ int nHeight,_In_opt_ HWND  hWndParent,_In_opt_ HMENU hMenu,\
	_In_opt_ HINSTANCE hInstance,_In_opt_ LPVOID lpParam);
typedef BOOL(WINAPI* FPShowWindow)(_In_ HWND hWnd,_In_ int  nCmdShow);
typedef BOOL(*FPUPDateWindow)(_In_ HWND hWnd);
typedef LRESULT(WINAPI* FPDispatchMessageW)(_In_ const MSG *lpmsg);
typedef BOOL(WINAPI* FPTranslateMessage)(_In_ const MSG *lpMsg);
typedef BOOL(WINAPI* FPGetMessageW)(_Out_ LPMSG lpMsg,_In_opt_ HWND hWnd,_In_ UINT  wMsgFilterMin,_In_ UINT wMsgFilterMax);
typedef VOID(WINAPI* FPPostQuitMessage)(_In_ int nExitCode);
typedef LRESULT(WINAPI* FPDefWindowProc)(_In_ HWND   hWnd,_In_ UINT   Msg,_In_ WPARAM wParam,_In_ LPARAM lParam);
typedef HWND(WINAPI* FPGetDlgItem)(_In_opt_ HWND hDlg,_In_ int nIDDlgItem);
typedef int (WINAPI* PFGetWindowTextLengthW)(_In_ HWND hWnd);
typedef int (WINAPI* PFGetWindowTextW)(_In_ HWND hWnd,_Out_ LPTSTR lpString,_In_ int nMaxCount);
typedef BOOL(WINAPI* PFSetWindowTextW)(_In_ HWND hWnd,_In_opt_ LPCTSTR lpString);

wchar_t g_wcBuf[100] = { 0 };
wchar_t g_PassWord[100] = L"MyPassWord";
wchar_t g_StrContext[100] = L"����������";
/////////////////////////////////////////////////////////////
DWORD g_dwImageBase;
DWORD g_oep;

void start();
PACKINFO g_PackInfo = { (DWORD)start };//DWORD dllOep; Decode

//////////////////////////////////////////////////////////////////////////
//��ʼ������ָ��
FPGetProcAddress    g_funGetProcAddress = nullptr;
FPLoadLibraryExW    g_funLoadLibraryExW = nullptr;
FPMessageBoxW        g_funMessageBoxW = nullptr;
HMODULE             hModuleKernel32 = nullptr;
HMODULE             hModuleUser32 = nullptr;
FPGetModuleHandleW     g_funGetModuleHandleW = nullptr;
FPRegisterClassW       g_funRegisterClassW = nullptr;
FPCreateWindowExW		g_funCreateWindowExW = nullptr;
FPShowWindow			g_funShowWindow= nullptr;
FPUPDateWindow			g_funUpdateWindow= nullptr;
FPDispatchMessageW		g_funDispatchMessageW = nullptr;
FPTranslateMessage		g_funTranslateMessage = nullptr;
FPGetMessageW			g_funGetMessageW = nullptr;
FPPostQuitMessage		g_funPostQuitMessage = nullptr;
FPDefWindowProc			g_funDefWindowProcW = nullptr;
FPGetDlgItem			g_funGetDlgItem = nullptr;
PFGetWindowTextLengthW   g_funGetWindowTextLengthW = nullptr;
PFGetWindowTextW		g_funGetWindowTextW = nullptr;
PFSetWindowTextW			g_funSetWindowTextW = nullptr;


int My_strcmp(const char *src, const char * dest)
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


//��ȡKernel32dll��ַ
//_declspec(naked) DWORD GetKernal32Base() {
//	////DWORD dwKernel32Addr = 0;
//	//__asm
//	//{
//	//	mov eax, dword ptr fs : [0x30] // PEB�ĵ�ַ
//	//	mov eax, [eax + 0x0C]          //  ָ��PEB_LDR_DATA�ṹ��ָ��
//	//	mov eax, [eax + 0x1C]          //  ģ���ʼ�������ͷָ��InInitializationOrderModuleList
//	//	mov eax, [eax]               // �б��еĵڶ�����Ŀ
//	//	mov eax, [eax + 0x08]          //��ȡ����Kernel32.dll��ַ
//	////mov dwKernel32Addr, esi
//	////pop esi
//	////mov eax, dwKernel32Addr
//	//	ret
//	//}
//
//	////return dwKernel32Addr;
//
//
//	
//
//}

DWORD GetKernal32Base() {
	DWORD dwKernel32Addr = 0;
	__asm
	{
		push eax
		mov eax, dword ptr fs : [0x30] // PEB�ĵ�ַ
		mov eax, [eax + 0x0C]          //  ָ��PEB_LDR_DATA�ṹ��ָ��
		mov eax, [eax + 0x1C]          //  ģ���ʼ�������ͷָ��InInitializationOrderModuleList
		mov eax, [eax]               // �б��еĵڶ�����Ŀ
		mov eax, [eax + 0x08]          //��ȡ����Kernel32.dll��ַ
		mov dwKernel32Addr, eax
		pop eax

	}

	return dwKernel32Addr;

}

DWORD GetFunAddrOfProcAddressAddr() {
	DWORD dwBaseOfKernel32 = GetKernal32Base();
	PIMAGE_DOS_HEADER pPos_Header = (PIMAGE_DOS_HEADER)dwBaseOfKernel32;
	PIMAGE_NT_HEADERS pNt_Header = (PIMAGE_NT_HEADERS)(pPos_Header->e_lfanew + dwBaseOfKernel32);
	//��ȡ��������
	PIMAGE_DATA_DIRECTORY pDataDir = pNt_Header->OptionalHeader.DataDirectory;
	PIMAGE_EXPORT_DIRECTORY pExPort = (PIMAGE_EXPORT_DIRECTORY)(dwBaseOfKernel32 + pDataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//��ȡ���������Ϣ
	DWORD dwFunCount = pExPort->NumberOfFunctions;//������������
	DWORD dwNameCount = pExPort->NumberOfNames;//���������Ƶ�����������
	DWORD dwNameRVA = pExPort->Name;

	PDWORD pEAT = PDWORD(dwBaseOfKernel32 + pExPort->AddressOfFunctions);//��ȡ��ַ��RVA
	PDWORD pENT = PDWORD(dwBaseOfKernel32 + pExPort->AddressOfNames);//��ȡ���Ʊ�RVA
	PWORD pEOT = PWORD(dwBaseOfKernel32 + pExPort->AddressOfNameOrdinals);//��ȡ��ű�RVA


	//���ѭ����������������ĵ�ַ�����������������ű�
	//����ű����ݸպ��ǵ�ַ������,˵����Ӧ���ˣ�����Ϊ����������Ʊ����ű�һһ��Ӧ��
	//Ȼ��ȥ����������Ʊ������ŵĵط������ǲ�������Ҫ�ĺ�������������GetproAddress
	for (DWORD i = 0;i < dwFunCount;i++) {
		DWORD dwOrdinal = pExPort->Base + i;//Base�ǵ�����������ʼ���
		//����ռ�����������ַ���п��ܴ������õ�ֵ������Ϊ0��ֵ��
		if (!pEAT[dwOrdinal]) {
			continue;
		}

		//��ȡ���
		//������ű����Ƿ���ֵ��ַ����±�ֵ��
		//���ж��Ƿ������Ƶ���

		//�ӱ���pEOT�л�ȡ��GetProcAddress�ĵ�ַ
		for (DWORD j = 0;j < dwNameCount;j++)
		{
			//��ű���Ԫ�ص�ֵ����Ӧ�ź�����ַ���λ��
			if (pEOT[j] == dwOrdinal) {
				//��ȡ���Ʊ��е�����
				DWORD dwNameOffset = pENT[j];
				char* pFunName = (char*)(dwBaseOfKernel32 + dwNameOffset);
				__asm {
					nop;
					nop;
				}
				//�ж��ǲ���GetProcAddress����
				if (!My_strcmp(pFunName, "GetProcAddress")) {
					//��ȡ��ַ������GetProcAddress�ĵ�ַ����
					DWORD dwFunAddrOffset = pEAT[dwOrdinal];
					return dwBaseOfKernel32 + dwFunAddrOffset;
				}
			}
		}
	}
	return -1;
}
void InitSomeAPI() {
	g_funGetProcAddress = (FPGetProcAddress)GetFunAddrOfProcAddressAddr();
	g_funLoadLibraryExW = (FPLoadLibraryExW)g_funGetProcAddress((HMODULE)GetKernal32Base(), "LoadLibraryExW");
	hModuleKernel32 = g_funLoadLibraryExW(L"Kernel32.dll", NULL, NULL);
	hModuleUser32 = g_funLoadLibraryExW(L"user32.dll", NULL, NULL);
	g_funMessageBoxW=(FPMessageBoxW)g_funGetProcAddress(hModuleUser32, "MessageBoxW");
	g_funGetModuleHandleW = (FPGetModuleHandleW)g_funGetProcAddress(hModuleKernel32, "GetModuleHandleW");
	g_funRegisterClassW = (FPRegisterClassW)g_funGetProcAddress(hModuleUser32, "RegisterClassW");
	g_funCreateWindowExW= (FPCreateWindowExW)g_funGetProcAddress(hModuleUser32, "CreateWindowExW");
	g_funShowWindow = (FPShowWindow)g_funGetProcAddress(hModuleUser32, "ShowWindow");
	g_funUpdateWindow=(FPUPDateWindow)g_funGetProcAddress(hModuleUser32, "UpdateWindow");
	g_funDispatchMessageW = (FPDispatchMessageW)g_funGetProcAddress(hModuleUser32, "DispatchMessageW");
	g_funTranslateMessage = (FPTranslateMessage)g_funGetProcAddress(hModuleUser32, "TranslateMessage");
	g_funGetMessageW = (FPGetMessageW)g_funGetProcAddress(hModuleUser32, "GetMessageW");
	g_funPostQuitMessage = (FPPostQuitMessage)g_funGetProcAddress(hModuleUser32, "PostQuitMessage");
	g_funDefWindowProcW = (FPDefWindowProc)g_funGetProcAddress(hModuleUser32, "DefWindowProcW");
	g_funGetDlgItem=(FPGetDlgItem)g_funGetProcAddress(hModuleUser32, "GetDlgItem");
	g_funGetWindowTextLengthW = (PFGetWindowTextLengthW)g_funGetProcAddress(hModuleUser32, "GetWindowTextLengthW");
	g_funGetWindowTextW = (PFGetWindowTextW)g_funGetProcAddress(hModuleUser32, "GetWindowTextW");
	g_funSetWindowTextW= (PFSetWindowTextW)g_funGetProcAddress(hModuleUser32, "SetWindowTextW");
	g_dwImageBase = (DWORD)g_funGetModuleHandleW(NULL);
	g_oep = g_PackInfo.TargetOep + g_dwImageBase;
}

//�޸��ض�λ
void FixReloc(char* pBuf) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_SECTION_HEADER pRelocSec = IMAGE_FIRST_SECTION(pNt);

	for (;;)
	{
		if (My_strcmp((char*)pRelocSec->Name, ".reloc"))
		{
			break;
		}
		pRelocSec++;
	}
	if (!My_strcmp((char*)pRelocSec->Name, ".reloc"))
		return;
	DWORD * temp;
	//��λ��ԭʼ�ض�λ�ڱ�

	PIMAGE_BASE_RELOCATION pReloc =
		(PIMAGE_BASE_RELOCATION)(pRelocSec->VirtualAddress + pBuf);
	while (pReloc->VirtualAddress != 0)
	{

		LPVOID rva = (LPVOID)((DWORD)pBuf + pReloc->VirtualAddress);
		DWORD BlockNum = (pReloc->SizeOfBlock - 8) / 2;
		if (BlockNum == 0) break;
		WORD *Offset = (WORD *)((DWORD)pReloc + 8);
		for (int i = 0; i < (int)BlockNum; i++)
		{
			if ((Offset[i] & 0xF000) != 0x3000)
				continue;
			temp = (DWORD*)((Offset[i] & 0xFFF) + (DWORD)rva);
			*temp = (*temp) - pNt->OptionalHeader.ImageBase + (DWORD)pBuf;
		}
		pReloc = (IMAGE_BASE_RELOCATION*)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
}


//������
bool isDubug() {
	DWORD Value=0;
	_asm
	{
		push eax;                 //TEB
		mov eax, fs:[0x30];         // PEB
		movzx eax, byte ptr[eax + 2];  //BeingDebugged
		mov dword ptr[Value], eax;   //ȡֵ
		pop eax;
	}
	if (Value)   //�ж�
	{
		g_funPostQuitMessage(0);
	}
	else
	{
		g_funMessageBoxW(NULL, L"û�е�����", L"��������", NULL);
	}
}


void Decode()
{
	unsigned char * pBuf = (unsigned char *)0x00400000 + g_PackInfo.dwReloc;
	for (int i = 0; i < g_PackInfo.dwSize; i++)
	{
		pBuf[i] ^= 0x15;
	}

}


int DoRun() {
	int a = 0;
	__asm
	{
		push eax
		push ebx
		push ecx
		push edi
		push esi
		////////////////////////////////////////////////////////////
		mov ecx, 20
		mov edi, offset g_PassWord;//��������
		mov esi, offset g_wcBuf
			repz cmpsb
			je  T
			jmp F
		T:
		mov a, 1
			F :
			////////////////////////////////////////////////////////////
			pop esi
			pop edi
			pop ecx
			pop ebx
			pop eax
	}
	return a;
}


LRESULT CALLBACK WindowProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
) {
	switch (uMsg)
	{
	case WM_CREATE:
	{
		//wchar_t WStr[35] = L"Window callback function trigger";
		//wchar_t WStr2[35] = L"Run";
		g_funMessageBoxW(NULL, L"Window callback function trigger", L"Run", NULL);
		DWORD dwStyle = ES_LEFT | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE;
		DWORD dwExStyle = WS_EX_CLIENTEDGE | WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR;
		HWND hWnd = g_funCreateWindowExW(
			dwExStyle, //dwExStyle ��չ��ʽ
			L"Edit", //lpClassName ��������
			g_StrContext, //lpWindowName ���ڱ���
			dwStyle, //dwStyle ������ʽ
			200, //x ���λ��
			100, //y ����λ��
			200, //nWidth ���
			30, //nHeight �߶�
			hwnd, //hWndParent �����ھ��
			(HMENU)0x1002, //ID
			g_funGetModuleHandleW(0), //hInstance Ӧ�ó�����
			NULL //lpParam ���Ӳ���
		);
		return 0;

	}

	case WM_COMMAND: 
	{
		WORD wId = LOWORD(wParam);
		WORD wCode = HIWORD(wParam);
		HANDLE hChild = (HANDLE)lParam;
		if (wId == 0x1001 && wCode == BN_CLICKED)
		{

			HWND hwndCombo = g_funGetDlgItem(hwnd, 0x1002);
			int cTxtLen = g_funGetWindowTextLengthW(hwndCombo);
			g_funGetWindowTextW(hwndCombo, g_wcBuf, 100);

			//wchar_t wStr[20] = L"Button to trigger";//��ť����
			//wchar_t wStr2[20] = L"Button to trigger";
			g_funMessageBoxW(NULL, L"Button to trigger", L"Button to trigger", NULL);
			wchar_t wStr3[20] = L"";
			if (DoRun() == 1) {
				g_funShowWindow(hwnd, SW_HIDE);//?
				Decode();
				HMODULE pThisDos = g_funGetModuleHandleW(NULL);
				FixReloc((char*)pThisDos);
				_asm jmp g_oep;
				//_asm jmp g_PackInfo.TargetOep;
				//wchar_t wStr[30] = L"Password is correct";
				//wchar_t wStr2[30] = L"Password is correct";
				g_funMessageBoxW(NULL, L"Password is correct", L"Password is correct", NULL);
			}
			else {
				//wchar_t wStr[30] = L"Wrong,Please Retry";
				//wchar_t wStr2[30] = L"Wrong,Please Retry";
				g_funMessageBoxW(NULL, L"Wrong,Please Retry", L"Wrong,Please Retry", NULL);
			}
			g_funSetWindowTextW(hwndCombo, wStr3);
			return 1;
		}
		break;

	}

	case WM_CLOSE:
	{
		g_funPostQuitMessage(0);
		break;
	}
	default:
		break;
	}
	// ����Ĭ�ϵĴ��ڴ������
	return g_funDefWindowProcW(hwnd, uMsg, wParam, lParam);
}


void MyCreateDialog() {
	MSG msg = { 0 };//��Ϣ
	g_funMessageBoxW(NULL, L"PassWord", L"PleaseInput", MB_YESNOCANCEL);
	//ע�ᴰ����
	WNDCLASS wcs = {};
	wcs.lpszClassName = L"manyouyou";
	wcs.lpfnWndProc = WindowProc;
	wcs.hbrBackground= (HBRUSH)(COLOR_CAPTIONTEXT + 7);
	g_funRegisterClassW(&wcs);

	//ע�ᴰ��
	HWND hWnd = g_funCreateWindowExW(0L, L"manyouyou", L"MyPassWord", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
		500, 200, 800, 800,
		NULL, NULL, NULL, NULL);
	g_funCreateWindowExW(0L, L"BUTTON", L"ok", WS_CHILD | WS_VISIBLE,
		300, 300,// �ڸ����ڵĿͻ�����λ�ã�
		100, 100,// �� ��
		hWnd,// ������
		(HMENU)0x1001,//�Ӵ��ڵ�ID
		g_funGetModuleHandleW(0), NULL); //GetModuleHandle
	

	isDubug();

	g_funShowWindow(hWnd, SW_SHOW);
	g_funUpdateWindow(hWnd);

	


	while (g_funGetMessageW(&msg, 0, 0, 0))
	{
		g_funTranslateMessage(&msg);
		g_funDispatchMessageW(&msg);
	}
}
_declspec(naked) void start()
{
	


	
	_asm
	{
		PUSH - 1
		PUSH 0
		PUSH 0
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		SUB ESP, 0x68
		PUSH EBX
		PUSH ESI
		PUSH EDI
		POP EAX
		POP EAX
		POP EAX
		ADD ESP, 0x68
		POP EAX
		MOV DWORD PTR FS : [0], EAX
		POP EAX
		POP EAX
		POP EAX
		POP EAX
		MOV EBP, EAX
	}
	InitSomeAPI();
	MyCreateDialog();
}