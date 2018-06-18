#pragma once
typedef struct _PACKINFO
{
	DWORD dllOep;    //这里存放着解壳代码的起始执行位置
	DWORD TargetOep; //加壳后目标程序的原始OEP
	DWORD dwReloc;
	DWORD dwSize;
}PACKINFO, *PPACKINFO;

extern "C" _declspec(dllexport) PACKINFO g_PackInfo;
