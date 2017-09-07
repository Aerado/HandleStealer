/*
* HandleStealer Demo DLL - by Aerado
* MinGW:
*  gcc -c DemoDll.c -o DemoDll.o
*  g++ -shared DemoDll.o -o DemoDll.dll -lwtsapi32
*/
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <imagehlp.h>
#include <wtsapi32.h>
#include <stdio.h>

int IntGlobalExample = 0;
char StringGlobalExample[32] = {0};

char *asprintf(char *fmt, ...)
{
	char *r=NULL;
	size_t sz;
	va_list args;
	va_start(args, fmt);
	if((sz=_vsnprintf(NULL, 0, fmt, args))&&(r=(char*)malloc(++sz))) _vsnprintf(r, sz, fmt, args);
	va_end(args);
	return r;
}

char *filename(char *path, BOOL woext)
{
	char *r=path, *aux;
	if(!r) return r;
	if((aux=strrchr(r, '\\'))) r=aux+1;
	if(woext) if((aux=strrchr(r, '.'))) *aux=0;
	return r;
}

char *ToExe(char *path)
{ return path?asprintf("%s.exe", filename(path, TRUE)):NULL; }

DWORD ServiceMessageBox(HANDLE hServer, LPSTR lpText, LPSTR lpCaption, UINT uType)
{
	DWORD r=0;
	WTSSendMessage(hServer, WTSGetActiveConsoleSessionId(), lpCaption, lpCaption?strlen(lpCaption):0, lpText, lpText?strlen(lpText):0, uType, 0, &r, TRUE);
	return r;
}

void MessageBoxInfo(void)
{
	char exe[MAX_PATH+1], *msg;
	if(GetModuleFileName(NULL, exe, sizeof(exe)-1))
		if((msg=asprintf("(%d)%s", GetCurrentProcessId(), filename(exe, FALSE)))) {
			ServiceMessageBox(NULL, msg, "Info", MB_OK);
			free(msg);
		}
}

BOOL SameArch(HANDLE hProc)
{
	BOOL r=FALSE, bIsCurWow64, bIsWow64;

	if(IsWow64Process(GetCurrentProcess(), &bIsCurWow64))
		if(IsWow64Process(hProc, &bIsWow64))
			r=(bIsCurWow64==bIsWow64);

	return r;
}

DWORD GetProcessIDByName(char *name)
{
	DWORD r=0;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	if(!name) return r;

	if((hProcessSnap=(HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))!=INVALID_HANDLE_VALUE) {
		pe32.dwSize=sizeof(PROCESSENTRY32);
		if(Process32First(hProcessSnap, &pe32))
			do {
				if(!stricmp(pe32.szExeFile, name)) r=pe32.th32ProcessID;
			} while(!r&&Process32Next(hProcessSnap, &pe32));
		CloseHandle(hProcessSnap);
	}

	return r;
}

DWORD WaitForProcess(char *name, DWORD timeout)
{
	DWORD r=0;
	timeout+=GetTickCount();
	while(!(r=GetProcessIDByName(name))&&timeout>GetTickCount()) Sleep(500);
	return r;
}

HANDLE FindThatHandle(DWORD dwProcessId, DWORD dwDesiredAccess)
{
	HANDLE r=NULL;
	DWORD i, dwSize=sizeof(SYSTEM_HANDLE_INFORMATION), dwCurId=GetCurrentProcessId();
	PSYSTEM_HANDLE_INFORMATION pHandleInfo;
	NTSTATUS status;

	FARPROC pfnNtQuerySystemInformation=GetProcAddress(GetModuleHandle("NTDLL"), "NtQuerySystemInformation");
	if(!pfnNtQuerySystemInformation) return r;

	if((pHandleInfo=(PSYSTEM_HANDLE_INFORMATION)malloc(dwSize))) {
		while((status=(NTSTATUS)pfnNtQuerySystemInformation(16, pHandleInfo, dwSize, &dwSize))==0xC0000004) pHandleInfo=(PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, dwSize*=2);
		if(NT_SUCCESS(status))
			for(i=0;i<pHandleInfo->Count&&!r;i++)
				if(pHandleInfo->Handle[i].OwnerPid==dwCurId&&(pHandleInfo->Handle[i].AccessMask&dwDesiredAccess)==dwDesiredAccess)
					if(GetProcessId((HANDLE)(DWORD_PTR)pHandleInfo->Handle[i].HandleValue)==dwProcessId) r=(HANDLE)(DWORD_PTR)pHandleInfo->Handle[i].HandleValue;
		free(pHandleInfo);
	}

	return r;
}

HANDLE CreateInterSectionThread(HANDLE hProc, LPVOID lpStartAddress, LPVOID lpParameter)
{
	HANDLE r=NULL;

	FARPROC pfnNtCreateThreadEx=GetProcAddress(GetModuleHandle("NTDLL"), "NtCreateThreadEx");
	if(!pfnNtCreateThreadEx) return r;

	if(lpStartAddress) pfnNtCreateThreadEx(&r, 0x1FFFFF, NULL, hProc, lpStartAddress, lpParameter, FALSE, NULL, NULL, NULL, NULL);

	return r;
}

void RebaseReloc(PIMAGE_BASE_RELOCATION Reloc, DWORD_PTR RelocSize, DWORD_PTR ImageBase, DWORD_PTR Delta)
{
	WORD *D;
	DWORD_PTR i, B, S=(DWORD_PTR)Reloc;

	while((DWORD_PTR)Reloc-S<RelocSize) {
		if(!Reloc->SizeOfBlock) break;
		B=ImageBase+(DWORD_PTR)Reloc->VirtualAddress;
		D=(WORD*)((DWORD_PTR)Reloc+sizeof(IMAGE_BASE_RELOCATION));
		for(i=0;i<(Reloc->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);i++) {
			if((*D>>12)==IMAGE_REL_BASED_DIR64) *(DWORD_PTR*)(B+(*D&0x0FFF)) += Delta;
			else if((*D>>12)==IMAGE_REL_BASED_HIGHLOW) *(DWORD*)(B+(*D&0x0FFF)) += (DWORD)Delta;
			else if((*D>>12)==IMAGE_REL_BASED_HIGH) *(WORD*)(B+(*D&0x0FFF)) += HIWORD(Delta);
			else if((*D>>12)==IMAGE_REL_BASED_LOW) *(WORD*)(B+(*D&0x0FFF)) += LOWORD(Delta);
			D++;
		}
		Reloc=(PIMAGE_BASE_RELOCATION)((DWORD_PTR)Reloc+Reloc->SizeOfBlock);
	}
}

void LazyManualMapping(HANDLE hProc, HANDLE hMod, LPTHREAD_START_ROUTINE lpFunction, FARPROC pfnAdjustGlobals)
{
	DWORD_PTR dwBase, dwCopyBase, dwNewBase, dwSize, dwDelta, RelVA, RelSize;
	PIMAGE_DOS_HEADER dHeader;
	PIMAGE_NT_HEADERS64 ntHeaders;

	if(!hProc||!hMod) return;

	dwBase=(DWORD_PTR)hMod;

	dHeader=(PIMAGE_DOS_HEADER)dwBase;
	if(dHeader->e_magic!=0x5A4D) return;

	ntHeaders=(PIMAGE_NT_HEADERS64)(dwBase+dHeader->e_lfanew);
	if(ntHeaders->Signature!=0x4550) return;

	dwSize=ntHeaders->OptionalHeader.SizeOfImage;

	RelVA=ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	RelSize=ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if(!(dwCopyBase=(DWORD_PTR)malloc(dwSize))) return;
	memcpy((LPVOID)dwCopyBase, (LPVOID)dwBase, dwSize);
	memset((LPVOID)dwCopyBase, 0, ntHeaders->OptionalHeader.SectionAlignment-1);
	if((dwNewBase=(DWORD_PTR)VirtualAllocEx(hProc, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) {
		dwDelta=dwNewBase-dwBase;
		RebaseReloc((PIMAGE_BASE_RELOCATION)(dwBase+RelVA), RelSize, dwCopyBase, dwDelta);
		WriteProcessMemory(hProc, (LPVOID)dwNewBase, (LPVOID)dwCopyBase, dwSize, NULL);
		if((pfnAdjustGlobals?(BOOL)pfnAdjustGlobals(hProc, dwDelta):TRUE))
			if(lpFunction) CloseHandle(CreateInterSectionThread(hProc, lpFunction+dwDelta, NULL));
	}
	free((LPVOID)dwCopyBase);
}

BOOL GlobalAdjustWORD(HANDLE hProc, DWORD_PTR dwDelta, LPVOID lpGlobal, WORD value)
{ return WriteProcessMemory(hProc, lpGlobal+dwDelta, &value, sizeof(value), NULL); }

BOOL GlobalAdjustDWORD(HANDLE hProc, DWORD_PTR dwDelta, LPVOID lpGlobal, DWORD value)
{ return WriteProcessMemory(hProc, lpGlobal+dwDelta, &value, sizeof(value), NULL); }

BOOL GlobalAdjustSTRING(HANDLE hProc, DWORD_PTR dwDelta, LPVOID lpGlobal, char *value)
{ return value?WriteProcessMemory(hProc, lpGlobal+dwDelta, value, strlen(value)+1, NULL):FALSE; }

BOOL GlobalAdjustBUFFER(HANDLE hProc, DWORD_PTR dwDelta, LPVOID lpGlobal, BYTE *value, size_t size)
{ return value&&size?WriteProcessMemory(hProc, lpGlobal+dwDelta, value, size, NULL):FALSE; }

INT_PTR WINAPI AdjustGlobals(HANDLE hProc, DWORD_PTR dwDelta)
{
	BOOL r=TRUE;
	if(!GlobalAdjustDWORD(hProc, dwDelta, &IntGlobalExample, -456)) r=FALSE;
	if(!GlobalAdjustSTRING(hProc, dwDelta, &StringGlobalExample, "format")) r=FALSE;
	return (INT_PTR)r;
}

DWORD WINAPI Startup(LPVOID lpParameter)
{
	DWORD r=0;
	char exe[MAX_PATH+1], *msg;
	if(GetModuleFileName(NULL, exe, sizeof(exe)-1))
		if((msg=asprintf("(%d)%s\n\n\nText %s%s... %d %x %.0f %i", GetCurrentProcessId(), filename(exe, FALSE), StringGlobalExample, "ting", 1, 2, 3.0f, IntGlobalExample))) {
			r=(DWORD)MessageBox(NULL, msg, "Hello!", MB_OK);
			free(msg);
		}
	return r;
}

void Initialize(HANDLE hMod)
{
	char path[MAX_PATH+1], *aux;
	DWORD dwPId;
	HANDLE hProc;

	MessageBoxInfo();

	if(GetModuleFileName(hMod, path, sizeof(path)-1))
		if((aux=ToExe(path))) {
			if((dwPId=WaitForProcess(aux, 20000)))
				if((hProc=FindThatHandle(dwPId, PROCESS_ALL_ACCESS)))
					if(SameArch(hProc)) LazyManualMapping(hProc, hMod, Startup, AdjustGlobals);
			free(aux);
		}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{ if(fdwReason==DLL_PROCESS_ATTACH) Initialize(hinstDLL); return FALSE; }
