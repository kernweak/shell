#pragma once
typedef struct _PACKINFO
{
	DWORD dllOep;    //�������Ž�Ǵ������ʼִ��λ��
	DWORD TargetOep; //�ӿǺ�Ŀ������ԭʼOEP
	DWORD dwReloc;
	DWORD dwSize;
}PACKINFO, *PPACKINFO;

extern "C" _declspec(dllexport) PACKINFO g_PackInfo;
