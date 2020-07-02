#include "stdafx.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <sys/stat.h>
#include <string>
#include <Dbghelp.h>
#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"
// Original, obfuscated code stored in ExInjector.cpp.debil
DWORD GetProccessId(char* name);

extern "C" __declspec(dllexport) bool file_exists(const std::string &dll) {
	struct stat _Stat;
	return (stat(dll.c_str(), &_Stat)==0);
}

char injectDllPID(int dwProcessId, char* dll) {
	HANDLE hProcess; 
	HMODULE hModule;
	char buf[50]={0};
	LPVOID lpParameter, lpStartAddress;

	if (!dwProcessId)
		return 2;

	hProcess=OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (!hProcess)
		return 3;

	if (!file_exists(dll))
		return 4;

	size_t len=strlen(dll);

	hModule = GetModuleHandleA("kernel32.dll");
	if (hModule == 0)
		return 5;
	else
		lpStartAddress=(LPVOID)GetProcAddress(hModule, "LoadLibraryA");
	lpParameter=(LPVOID)VirtualAllocEx(hProcess, NULL, len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if (lpParameter == 0)
		return 6;
	else
		WriteProcessMemory(hProcess, (LPVOID)lpParameter, dll, len, NULL);
	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpStartAddress, (LPVOID)lpParameter, NULL, NULL);
	(hProcess);
	return 0;
}

extern "C" __declspec(dllexport) int injectDll(char* name, char* dll) {
	DWORD dwProcessId = GetProccessId(name);

	if (dwProcessId != 0)
		return injectDllPID(dwProcessId, dll);

	return 1;
}

extern "C" __declspec(dllexport) bool IsAdmin()
{
	bool IsAdmin = FALSE;
	HANDLE TokenHandle = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle))
	{
		TOKEN_ELEVATION TokenInformation;
		DWORD ReturnLength = sizeof(TOKEN_ELEVATION);

		if(GetTokenInformation(TokenHandle, TokenElevation, &TokenInformation, sizeof(TokenInformation), &ReturnLength))
			IsAdmin=TokenInformation.TokenIsElevated;
	}

	if (TokenHandle)
		CloseHandle(TokenHandle);

	return IsAdmin;
}

LPSTR UnicodeToAnsi(LPCWSTR pe32)
{
	if (pe32 == NULL)
		return NULL;

	int cw = lstrlenW(pe32);

	if (cw == 0)
	{
		CHAR*psz = new CHAR[1];
		*psz = '\0';
		return psz;
	}

	int cc = WideCharToMultiByte(CP_ACP, 0, pe32, cw, NULL, 0, NULL, NULL);

	if (cc == 0)
		return NULL;

	#pragma warning(disable:26451)
	CHAR* psz = new CHAR[cc+1];
	#pragma warning(default:26451) 
	cc = WideCharToMultiByte(CP_ACP, 0, pe32, cw, psz, cc, NULL, NULL);

	if(cc == 0)
	{
		delete[] psz;
		return NULL;
	}

	psz[cc] = '\0';
	return psz;
}

DWORD GetProccessId(char* name)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32))
	{
		do {
			char* UTA = UnicodeToAnsi(pe32.szExeFile);

			if (strcmp(UTA, name) == 0)
			{
				delete[] UTA;
				return pe32.th32ProcessID;
			}

			delete[] UTA;
		} while (Process32Next(hSnapshot, &pe32));
	}

	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return 0;
}
