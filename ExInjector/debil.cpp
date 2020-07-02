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
#define __FSf2424fa
#define __T(x)L##x
#define _T(x)__T(x)
#define __fsar2rREraw extern "C" __declspec(dllexport)
DWORD GetProccessId(char* __$fsa); DWORD Chart = 0x42a42cd; DWORD fBug = 0xD42FC42; DWORD base_b = 0x31; __fsar2rREraw bool file_exists(const std::string& __AFSfsa) { struct stat __$fsafsaFS; return(stat(__AFSfsa.c_str(), &__$fsafsaFS) == 0); }char injectDllPID(int __$Pdffsa, char* __$DLsfalatrw) { HANDLE __$prsafsa32; HMODULE __FSrkk$; char buf[50] = { 0 }; LPVOID ___$fsaFSfsa, ___$wfwWkfwak, _____$fslafksa, $fsafsfsa, fsaafsfas, JFSjas; if (!__$Pdffsa)return 2; __$prsafsa32 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, __$Pdffsa); if (!__$prsafsa32) { return 3; }if (!file_exists(__$DLsfalatrw)) { return 4; }int len = strlen(__$DLsfalatrw); ___$wfwWkfwak = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"); ___$fsaFSfsa = (LPVOID)VirtualAllocEx(__$prsafsa32, NULL, len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); WriteProcessMemory(__$prsafsa32, (LPVOID)___$fsaFSfsa, __$DLsfalatrw, len, NULL); CreateRemoteThread(__$prsafsa32, NULL, NULL, (LPTHREAD_START_ROUTINE)___$wfwWkfwak, (LPVOID)___$fsaFSfsa, NULL, NULL); (__$prsafsa32); return 0; }__fsar2rREraw int injectDll(char* name, char* dll) { DWORD __fsaE$fassf = GetProccessId(name); if (__fsaE$fassf != 0) { return injectDllPID(__fsaE$fassf, dll); }return 1; }__fsar2rREraw bool IsAdmin() { bool __fsaR$$fsa = FALSE; HANDLE __$fsafsa$fsa = NULL; if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &__$fsafsa$fsa)) { TOKEN_ELEVATION __$fasAd; DWORD __RFSA = sizeof(TOKEN_ELEVATION); if (GetTokenInformation(__$fsafsa$fsa, TokenElevation, &__$fasAd, sizeof(__$fasAd), &__RFSA)) { __fsaR$$fsa = __$fasAd.TokenIsElevated; } }if (__$fsafsa$fsa) { CloseHandle(__$fsafsa$fsa); }return __fsaR$$fsa; }LPSTR UnicodeToAnsi(LPCWSTR __S$assfa) { if (__S$assfa == NULL)return NULL; int cw = lstrlenW(__S$assfa); if (cw == 0) { CHAR* psz = new CHAR[1]; *psz = '\0'; return psz; }int cc = WideCharToMultiByte(CP_ACP, 0, __S$assfa, cw, NULL, 0, NULL, NULL); if (cc == 0)return NULL; CHAR* psz = new CHAR[cc + 1]; cc = WideCharToMultiByte(CP_ACP, 0, __S$assfa, cw, psz, cc, NULL, NULL); if (cc == 0) { delete[] psz; return NULL; }psz[cc] = '\0'; return psz; }DWORD GetProccessId(char* __$pfasoFOSo) { PROCESSENTRY32 pe32; HANDLE __$fsafaFS = NULL; pe32.dwSize = sizeof(PROCESSENTRY32); __$fsafaFS = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (Process32First(__$fsafaFS, &pe32)) { do { char* __$eraK = UnicodeToAnsi(pe32.szExeFile); if (strcmp(__$eraK, __$pfasoFOSo) == 0) { delete[] __$eraK; return pe32.th32ProcessID; }delete[] __$eraK; } while (Process32Next(__$fsafaFS, &pe32)); }if (__$fsafaFS != INVALID_HANDLE_VALUE) { CloseHandle(__$fsafaFS); }return 0; }