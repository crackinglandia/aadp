/*
 $Id: antidbglib.cpp 22 2012-02-19 05:59:43Z crackinglandia $ 

 Anti-Anti-Debugging Library - LGPL 3.0

 Copyright (C) 2010 +NCR/CRC! [ReVeRsEr] http://crackinglandia.blogspot.com

 This library is free software: you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation, either
 version 3 of the License, or any later version.
 
 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.
 
 You should have received a copy of the GNU Lesser General Public
 License along with this library.  If not, see <http://www.gnu.org/licenses/>.

 Author: Nahuel C. Riva
 Date: November, 2010
 @: nahuelriva@gmail.com
 Blog: http://crackinglandia.blogspot.com
 Twitter: @crackinglandia

 References: 
 - http://pferrie.tripod.com/
 - http://www.openrce.org/reference_library/anti_reversing
 - http://www.veracode.com/blog/2008/12/anti-debugging-series-part-i/
 - http://www.veracode.com/blog/2008/12/anti-debugging-series-part-ii/
 - http://www.veracode.com/blog/2009/01/anti-debugging-series-part-iii/
 - http://www.veracode.com/blog/2009/02/anti-debugging-series-part-iv/
 - http://www.symantec.com/connect/de/articles/windows-anti-debug-reference

 ** 17/11/2010 **:
 - Added some functions to defeat the following tricks:
	- ZwQueryObject
	- ZwOpenProcess
	- FindWindow
	- UnhandledExceptionFilter
	- SuspendThread
	- BlockInput
	- TerminateProcess
	- Process32Next
	- Module32Next
	- ZwQuerySystemInformation
** 18/11/2010 **:
	- fixed a bug in hd_Zw* functions when we search for the function pattern (reported by LFC-AT).
	- added OutputDebugStringW patch (reported by chessmod101).
** 23/11/2010 **:
	- added fix for hd_GetTickCount, SuspendThread and TerminateProcess under Windows 7. 
	GetTickCount (TerminateProcess & SuspendThread too)function's code is in kernelbase.dll not in kernel32.dll
	kernel32.dll just hold the forwarders jumps to the GetTickCount's original code.
	- added fix for UnhandledExceptionFilter under XP reported by marciano.
** 24/11/2010 **
	- added fix in hd_OutputDebugString in order to support Windows 7.
** 30/11/2010 **
	- fixed some bugs reported by LCF-AT in the SuspendThread, TerminateProcess, Process32Next, 
	Module32Next, OutputDebugString and UnhandledExceptionFilter hooks under XP SP0.
** 07/12/2010 **
	- added the hd_GetProcInfo() and FindEx functions. Refactored the GetPEBAddress().
	- removed TitanEngine.lib and SDK.h from the project. We only use the FindEx from it, so, 
	it has no sense to maintain that dependency.
*/

#include "stdafx.h"

// Global declarations
lpfNtQueryInformationProcess pNtQueryInformationProcess = NULL;
LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL hd_GetVersionEx(LPOSVERSIONINFOEX osvi)
{
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if(!(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)))
		return FALSE;

}

// from TitanEngine SDK - Property of ReversingLabs www.reversinglabs.com
long long __stdcall hd_FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard)
{
	/*
		Description: Searches for a specific pattern of bytes in a process.
		Syntax: long long FindEx(
				__in HANDLE hProcess, 
				__in LPVOID MemoryStart,
				__in DWORD  MemorySize,
				__in LPVOID SearchPattern,
				__in DWORD  PatternSize, 
				__in_opt    WildCard
				);
		Parameters: - 
		Return value: -
	*/

	int i = NULL;
	int j = NULL;
	ULONG_PTR Return = NULL;
	LPVOID ueReadBuffer = NULL;
	PUCHAR SearchBuffer = NULL;
	PUCHAR CompareBuffer = NULL;
	MEMORY_BASIC_INFORMATION memoryInformation = {};
	ULONG_PTR ueNumberOfBytesRead = NULL;
	LPVOID currentSearchPosition = NULL;
	DWORD currentSizeOfSearch = NULL;
	BYTE nWildCard = NULL;

	if(WildCard == NULL){WildCard = &nWildCard;}
	if(hProcess != NULL && MemoryStart != NULL && MemorySize != NULL){
		if(hProcess != GetCurrentProcess()){
			ueReadBuffer = VirtualAlloc(NULL, MemorySize, MEM_COMMIT, PAGE_READWRITE);
			if(!ReadProcessMemory(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead)){
				if(ueNumberOfBytesRead == NULL){
					if(VirtualQueryEx(hProcess, MemoryStart, &memoryInformation, sizeof memoryInformation) != NULL){
						MemorySize = (DWORD)((ULONG_PTR)memoryInformation.BaseAddress + memoryInformation.RegionSize - (ULONG_PTR)MemoryStart);
						if(!ReadProcessMemory(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead)){
							VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
							return(NULL);
						}else{
							SearchBuffer = (PUCHAR)ueReadBuffer;
						}
					}else{
						VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
						return(NULL);
					}
				}else{
					SearchBuffer = (PUCHAR)ueReadBuffer;
				}
			}else{
				SearchBuffer = (PUCHAR)ueReadBuffer;
			}
		}else{
			SearchBuffer = (PUCHAR)MemoryStart;
		}
		__try{
			CompareBuffer = (PUCHAR)SearchPattern;
			for(i = 0; i < (int)MemorySize && Return == NULL; i++){
				for(j = 0; j < (int)PatternSize; j++){
					if(CompareBuffer[j] != *(PUCHAR)WildCard && SearchBuffer[i + j] != CompareBuffer[j]){
						break;
					}
				}
				if(j == (int)PatternSize){
					Return = (ULONG_PTR)MemoryStart + i;
				}
			}
			VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(Return);
		}__except(EXCEPTION_EXECUTE_HANDLER){
			VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
			return(NULL);
		}
	}else{
		return(NULL);
	}
}

OSFAMILY __stdcall hd_GetOSFamily(void)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/
	
	OSFAMILY OsFamily = UnknownOS;
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO SystemInfo;

	GetSystemInfo(&SystemInfo);

	if(hd_GetVersionEx(&osvi))
	{
		switch(osvi.dwMajorVersion)
		{
			case 5:
					switch(osvi.dwMinorVersion)
					{
						case 0:
								OsFamily = Windows2000;
								break;

						case 1: 
								OsFamily = WindowsXP;
								break;

						case 2: 

								if(osvi.wProductType == VER_NT_WORKSTATION && SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
								{
									OsFamily = WindowsXP64;
								}
								else
								{
									if(GetSystemMetrics(SM_SERVERR2) == 0)
									{
										OsFamily = Windows2003;
									}
									else
									{
										if(osvi.wSuiteMask & VER_SUITE_WH_SERVER)
										{
											OsFamily = WindowsHomeServer; 
										}
										else
										{
											if(GetSystemMetrics(SM_SERVERR2) != 0)
											{
												OsFamily = Windows2003R2;
											}
										}
									}
								}
								break;
						default: break;
					}
					break;
			case 6:
					switch(osvi.dwMinorVersion)
					{
						case 0: 
								if(osvi.wProductType != VER_NT_WORKSTATION)
									OsFamily = Windows2008;
								else
									OsFamily = WindowsVista;
								break;
						case 1: 
								if(osvi.wProductType != VER_NT_WORKSTATION)
									OsFamily = Windows2008R2;
								else
									OsFamily = Windows7;
								break;
						default: break;
					}
					break;
			default: break;
		}
	}
	return OsFamily;
}

BOOL __stdcall hd_IsOSWorkstationEdition(void)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	OSVERSIONINFOEX osvi;

	if(hd_GetVersionEx(&osvi))
	{
		if(osvi.wProductType == VER_NT_WORKSTATION)
			return TRUE;
	}
	return FALSE;
}

BOOL __stdcall hd_IsOSServerEdition(void)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	OSVERSIONINFOEX osvi;
	if(hd_GetVersionEx(&osvi))
	{
		if(osvi.wProductType == VER_NT_SERVER || osvi.wProductType == VER_NT_DOMAIN_CONTROLLER)
			return TRUE;
	}
	return FALSE; 
}

BOOL __stdcall hd_IsWOW64(void)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	// http://msdn.microsoft.com/en-us/library/ms684139%28v=vs.85%29.aspx

    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
    GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(fnIsWow64Process != NULL)
    {
        if (fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            return bIsWow64; 
        }
    }
    return bIsWow64;
}

int __stdcall hd_GetOSServicePack(void)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	OSVERSIONINFOEX osvi;
	
	if(hd_GetVersionEx(&osvi))
	{
		return osvi.wServicePackMajor; 
	}
	return -1;
}

// from TitanEngine SDK - Property of ReversingLabs www.reversinglabs.com
long long __stdcall hd_Find(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard)
{
	/*
		Description: Finds a specific pattern of bytes in the current process. 
		Syntax: long long Find(
					__in LPVOID MemoryStart, 
					__in DWORD  MemorySize, 
					__in LPVOID SearchPattern, 
					__in DWORD  PatternSize, 
					__in_opt LPBYTE WildCard
					);
		Parameters: -
		Return value: If the function success, returns the address of the first match where the pattern was found.
					  If the function failed, the return value is NULL. 
	*/

	return hd_FindEx(GetCurrentProcess(), MemoryStart, MemorySize, SearchPattern, PatternSize, WildCard);
}

BOOL __stdcall hd_GetProcInfo(HANDLE hProcess, PPROCESS_BASIC_INFORMATION pInfo)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	HMODULE hNtDll;
	if ((hNtDll = GetModuleHandleA("ntdll.dll")) == NULL)
		return FALSE;

	pNtQueryInformationProcess = (lpfNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	return(pNtQueryInformationProcess(hProcess, 0 , pInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL) == 0);
}

HANDLE __stdcall hd_GetProcHandleByPid(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	HANDLE hProcess = NULL;

	if(!pid)
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	else
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return hProcess;
}

DWORD __stdcall hd_GetProcPidByHandle(HANDLE hProcess)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	DWORD pid = -1;
	PROCESS_BASIC_INFORMATION pInfo;

	if (hProcess != NULL)
	{
		if(hd_GetProcInfo(hProcess, &pInfo))
			return pInfo.UniqueProcessId;
	}
	return -1;
}

void* __stdcall hd_GetPEBAddress(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	HANDLE hProcess;
	PROCESS_BASIC_INFORMATION pInfo;

	hProcess = hd_GetProcHandleByPid(pid);
	if(hProcess != NULL)
	{
		if(hd_GetProcInfo(hProcess, &pInfo))
			return pInfo.PebBaseAddress;
	}
	return FALSE; 
}

BOOL __stdcall hd_IsDebuggerPresent(DWORD pid)
{
		/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	; This function overwrite the PEB->BeingDebugged field. So, we avoid the 
	; IsDebuggerPresent API call and the direct access to the PEB field.
	; Two birds with one stone :P
	; Case 1:
	; call IsDebuggerPresent
	; test eax, eax
	; jne @DebuggerDetected
	; Case 2:
	; mov eax, fs:[30h]
	; mov eax, byte [eax+2]
	; test eax, eax
	; jne @DebuggerDetected  
	*/
	DWORD lpNumberOfBytes, Peb;
	LPVOID BeingDebugged = NULL;
	HANDLE hProc;
	
	hProc = hd_GetProcHandleByPid(pid);
	Peb = (DWORD)hd_GetPEBAddress(pid);
	Peb += 2;

	if(!WriteProcessMemory(hProc, (LPVOID)Peb, &BeingDebugged, 1, &lpNumberOfBytes))
		return FALSE;
	return TRUE;
}

BOOL __stdcall hd_NtGlobalFlags(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	; mov eax, fs:[30h] eax->PEB
	; mov eax, [eax+68h] eax->PEB.NtGlobalFlags
	; and eax, 0x70
	; test eax, eax
	; jne @DebuggerDetected 
	*/
	DWORD lpNumberOfBytes, Peb;
	LPVOID lpBuffer = NULL;
	HANDLE hProc;

	hProc = hd_GetProcHandleByPid(pid);

	Peb = (DWORD)hd_GetPEBAddress(pid);
	Peb += 0x68;

	if(!WriteProcessMemory(hProc, (LPVOID)Peb, &lpBuffer, 4, &lpNumberOfBytes))
		return FALSE;
	return TRUE;
}

BOOL __stdcall hd_HeapFlagsOnPEB(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	; Example:
	; mov eax, fs:[30h]
	; mov eax, [eax+18h] ;process heap
	; mov eax, [eax+10h] ;heap flags
	; test eax, eax
	; jne @DebuggerDetected
	*/
	DWORD lpNumberOfBytes, Peb, HeapFlags;
	LPVOID lpBuffer = NULL;
	HANDLE hProc;
	BOOL ret;

	hProc = hd_GetProcHandleByPid(pid);

	Peb = (DWORD)hd_GetPEBAddress(pid);
	Peb += 0x18;

	ret = ReadProcessMemory(hProc, (LPVOID)Peb, &lpBuffer, 4, &lpNumberOfBytes);
	if(ret != 0)
	{
		HeapFlags = (DWORD)lpBuffer+0x10;
		lpBuffer = NULL;

		if(!WriteProcessMemory(hProc, (LPVOID)HeapFlags, &lpBuffer, 4, &lpNumberOfBytes))
			return FALSE;	
	}
	return TRUE;
}

BOOL __stdcall hd_GetTickCount(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	 Replaces the following code in GetTickCount:
	 7624973A     03C1           ADD EAX,ECX
	 7624973C   . C3             RETN

	 with:
	 XOR EAX, EAX
	 RET
	*/
	BYTE pattern = 0xc3;
	BYTE WildCard = 0;
	void* gtcAddr = NULL;
	BYTE pb[] = {0x33, 0xc0, 0xc3};
	DWORD lpNumberOfBytesWritten;
	HANDLE hProc = NULL;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION)
		gtcAddr = (void*)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "GetTickCount");
	else
		gtcAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");

	if(!WriteProcessMemory(hProc, (LPVOID)(gtcAddr), &pb, sizeof(pb), &lpNumberOfBytesWritten))
		return FALSE; 
	return TRUE;
}

BOOL __stdcall hd_HookOutputDebugString(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE OdsPattern[] = {0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00};
	BYTE OdswPattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x56, 0xFF, 0x75, 0x08};
	BYTE OdswWin7Pattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x56, 0x57, 0xFF, 0x75, 0x08};
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE ret4[] = {0xc2, 0x04, 0x00};
	BYTE pb[] = {0x60, 0x8B, 0x44, 0x24, 0x24, 0xC6, 0x00, 0x00, 0xC6, 0x40, 0x01, 0x00, 0x61, 0x68, 0x34, 0x02, 0x00, 0x00, 0xE9, 0x90, 0x90, 0x90, 0x90};
	BYTE WildCard = 0;
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, InitAddr, DestAddr, jmp_offset;
	void* patternAddr = NULL;
	void* odsAddr = NULL;
	LPVOID RemoteSectionAddr = NULL;
	OSVERSIONINFOEX osvi;
	OSFAMILY OS;

	OS = (OSFAMILY)hd_GetOSFamily();
	
	hProc = hd_GetProcHandleByPid(pid);
	if(hProc != NULL)
	{
		// Hook for OutputDebugStringA
		if(OS == Windows7 && hd_IsOSWorkstationEdition())
			odsAddr = (void*)GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "OutputDebugStringA");
		else
			odsAddr = (void*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "OutputDebugStringA");

		if(odsAddr != NULL)
		{
			patternAddr = (void*)hd_FindEx(hProc, odsAddr, 0x0100, &OdsPattern, sizeof(OdsPattern), &WildCard);

			if(patternAddr != NULL)
			{
				RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				// write the jmp to the section
				jmp_offset = (DWORD)RemoteSectionAddr - (DWORD)odsAddr - sizeof(JmpToSection);
				*(DWORD*)&JmpToSection[1] = jmp_offset;
			
				if(WriteProcessMemory(hProc, (LPVOID)odsAddr, &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
				{
					// write the code into the section
					if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
					{
						// calculate the jmp to the instruction after the hook
						// we reuse the JmpToSection variable. The inconditional jmp is always 5 bytes long.
						InitAddr = (DWORD)RemoteSectionAddr + (sizeof(pb) - sizeof(JmpToSection));
						DestAddr = (DWORD)odsAddr + 5;
						jmp_offset = DestAddr - InitAddr - 5;
						*(DWORD*)&JmpToSection[1] = jmp_offset;
						if(WriteProcessMemory(hProc, (LPVOID)InitAddr, &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
						{
							// Hook for OutputDebugStringW
							if(OS == Windows7 && hd_IsOSWorkstationEdition()) // if win7 ...
							{
								odsAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "OutputDebugStringW");
								patternAddr = (void*)hd_FindEx(hProc, odsAddr, 0x0100, &OdswWin7Pattern, sizeof(OdswPattern), &WildCard);
							}
							else
							{
								odsAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OutputDebugStringW");
								if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 && osvi.wServicePackMajor == 0) // if xp sp0
									patternAddr = (void*)hd_FindEx(hProc, odsAddr, 0x0100, &OdswPattern[2], sizeof(OdswPattern) - 2, &WildCard);
								else
									patternAddr = (void*)hd_FindEx(hProc, odsAddr, 0x0100, &OdswPattern, sizeof(OdswPattern), &WildCard);
							}

							if(odsAddr != NULL)
							{
								if(patternAddr != NULL)
								{
									if(WriteProcessMemory(hProc, (LPVOID)patternAddr, &ret4, sizeof(ret4), &lpNumberOfBytesWritten))
										return TRUE;
								}
							}
						}
					}
				}
			}
		}
	}
	return FALSE;
}

BOOL __stdcall hd_HookZwQueryInformationProcess(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	Example:
	push 0
	push 4
	push offset isdebugged
	push 7 ;ProcessDebugPort
	push -1
	call NtQueryInformationProcess
	test eax, eax
	jne @ExitError
	cmp isdebugged, 0
	jne @DebuggerDetected
	*/
	BYTE WildCard = 0;
	// the last to bytes (0xff, 0x12) are not searched, in XP SP0 there is no CALL [EDX], is CALL EDX.
	// so, we only search for the MOVs.
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12}; 
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE pb[] = {0xFF, 0x12, 0x83, 0x7C, 0x24, 0x08, 0x07, 0x75, 0x11, 0x8B, 0x44, 0x24, 0x0C, 0xC7, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x33, 0xC0, 0xC2, 0x14, 0x00, 0xEB, 0x1D, 0x83, 0x7C, 0x24, 0x08, 0x00, 0x75, 0x13, 0x8B, 0x44, 
		0x24, 0x0C, 0x60, 0x8B, 0x78, 0x10, 0x89, 0x78, 0x14, 0x61, 0x33, 0xC0, 0xC2, 0x14, 0x00, 0xEB, 
		0x03, 0xC2, 0x14, 0x00};
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, jmp_offset;
	void* zwqipAddr = NULL;
	void* pAddress = NULL;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;
	LPVOID RemoteSectionAddr = NULL;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) // Windows XP
	{
		if(osvi.wServicePackMajor == 0) // SP0
			*(BYTE*)&pb[1] = 0xd2;
	}

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	zwqipAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");
	pAddress = (void*)hd_FindEx(hProc, zwqipAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress != NULL)
	{
		RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(RemoteSectionAddr != NULL)
		{
			// write the hook into the remote section
			if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			{
				jmp_offset = (DWORD)RemoteSectionAddr - ((DWORD)zwqipAddr+10) - 5;
				// write the jmp to the hook in the ret of the hooked function
				*(DWORD *)&JmpToSection[1] = jmp_offset;
				
				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)zwqipAddr+10), &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
					return TRUE;
			}

		}
	}

	return FALSE;
}

BOOL __stdcall hd_HookZwSetInformationThread(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	/*
	Example:
	push 0
	push 0
	push 11h ;ThreadHideFromDebugger
	push -2
	call NtSetInformationThread
	;thread detached if debugged
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12}; 
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE pb[] = {0x83, 0x7C, 0x24, 0x08, 0x11, 0x75, 0x03, 0xC2, 0x10, 0x00, 0xB8, 0x32, 0x01, 0x00, 0x00, 0xE9, 0x90, 0x90, 0x90, 0x90};
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, jmp_offset, InitAddr, DestAddr;
	void* zwsitAddr = NULL;
	void* pAddress = NULL;
	LPVOID RemoteSectionAddr = NULL;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) // Windows XP
	{
		if(osvi.wServicePackMajor == 3 && osvi.wServicePackMinor == 0) // SP3
		{
			*(DWORD*)&pb[11] = 0xe5; // constant for ZwSetInformationThread in Windows XP SP3
		}
		else
		{
			if(osvi.wServicePackMajor == 0 || osvi.wServicePackMajor == 1 || osvi.wServicePackMajor == 2)
			{
				*(DWORD*)&pb[11] = 0x9a; // constant for ZwSetInformationThread in Windows XP SP0/SP1/SP2
			}
		}
	}
	else
	{
		if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION) // Windows 7
		{
			if(osvi.wServicePackMajor == 0) // Service Pack 0
				*(DWORD*)&pb[11] = 0x14f;
		}
	}

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	zwsitAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetInformationThread");
	pAddress = (void*)hd_FindEx(hProc, zwsitAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress != NULL)
	{
		RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(RemoteSectionAddr != NULL)
		{
			// write the hook into the remote section
			if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			{
				jmp_offset = (DWORD)RemoteSectionAddr - ((DWORD)zwsitAddr) - 5;
				// write the jmp to the hook in the ret of the hooked function
				*(DWORD *)&JmpToSection[1] = jmp_offset;
				
				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)zwsitAddr), &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
				{
					// write a jmp to the original function at the end of the injected code
					InitAddr = (DWORD)RemoteSectionAddr + (sizeof(pb) - 5); 
					DestAddr = (DWORD)pAddress + 5;
					jmp_offset = DestAddr - InitAddr - 5;
					*(DWORD*)&JmpToSection[1] = jmp_offset;

					if(WriteProcessMemory(hProc, (LPVOID)InitAddr, &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
						return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL __stdcall hd_ZwQuerySystemInformation(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12}; 
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE pb[] = {0xFF, 0x12, 0x83, 0x7C, 0x24, 0x04, 0x23, 0x75, 0x15, 0x60, 0x8B, 0x7C, 0x24,
		0x28, 0x8B, 0x4C, 0x24, 0x2C, 0x33, 0xC0, 0xF3, 0xAA, 0x61, 0x33, 0xC0, 0xC2, 0x10, 0x00,
		0xEB, 0x03, 0xC2, 0x10, 0x00};
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, jmp_offset;
	void* zwqsiAddr = NULL;
	void* pAddress = NULL;
	LPVOID RemoteSectionAddr = NULL;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	zwqsiAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
	pAddress = (void*)hd_FindEx(hProc, zwqsiAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress != NULL)
	{
		RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(RemoteSectionAddr != NULL)
		{
			// write the hook into the remote section
			if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			{
				jmp_offset = (DWORD)RemoteSectionAddr - ((DWORD)zwqsiAddr+10) - 5;
				// write the jmp to the hook in the ret of the hooked function
				*(DWORD *)&JmpToSection[1] = jmp_offset;
				
				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)zwqsiAddr+10), &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
					return TRUE;
			}

		}
	}

	return FALSE;
}

BOOL __stdcall hd_SuspendThread(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	LPVOID stAddr = NULL;
	LPVOID patternAddr = NULL;
	BYTE pb[] = {0xc2, 0x04, 0x00};
	BYTE stPattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x8D, 0x45, 0x08};
	BYTE WildCard = 0;
	HANDLE hProc;
	DWORD lpNumberOfBytesWritten;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION)
		stAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "SuspendThread");
	else
		stAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SuspendThread");

	if(stAddr == NULL)
		return FALSE; 

	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 && osvi.wServicePackMajor == 0)
		patternAddr = (void*)hd_FindEx(hProc, stAddr, 0x0100, &stPattern[2], sizeof(stPattern) - 2, &WildCard);
	else
		patternAddr = (void*)hd_FindEx(hProc, stAddr, 0x0100, &stPattern, sizeof(stPattern), &WildCard);

	if(patternAddr != NULL)
	{
		if(WriteProcessMemory(hProc, (LPVOID)stAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			return TRUE;
	}
	return FALSE;
}

BOOL __stdcall hd_BlockInput(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12};
	BYTE pb[3] = {0xc2, 0x04, 0x00};
	void* pAddress = NULL;
	void* biAddr = NULL;
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten;;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	biAddr = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "BlockInput");
	pAddress = (void*)hd_FindEx(hProc, biAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(!WriteProcessMemory(hProc, (LPVOID)pAddress, &pb, sizeof(Pattern), &lpNumberOfBytesWritten))
		return FALSE;
	return TRUE;
}

BOOL __stdcall hd_TerminateProcess(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00};
	BYTE Pattern2[] = {0x83, 0x7C, 0x24, 0x04, 0x00, 0x74, 0x00};
	BYTE pb[3] = {0xc2, 0x08, 0x00};
	void* pAddress = NULL;
	void* tpAddr = NULL;
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten;;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION)
		tpAddr = (void*)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "TerminateProcess");
	else
		tpAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");

	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 && osvi.wServicePackMajor == 0)
		pAddress = (void*)hd_FindEx(hProc, tpAddr, 0x0100, &Pattern2, sizeof(Pattern2), &WildCard);
	else
		pAddress = (void*)hd_FindEx(hProc, tpAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(!WriteProcessMemory(hProc, (LPVOID)pAddress, &pb, sizeof(pb), &lpNumberOfBytesWritten))
		return FALSE;
	return TRUE;
}

BOOL __stdcall hd_ZwOpenProcess(DWORD pid, DWORD dbgPid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12}; 
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE pb[] = {0x60, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x8B, 0x4C, 0x24, 0x24, 0x8B, 0x09, 0x3B,
		0xC1, 0x75, 0x08, 0x61, 0xB8, 0x22, 0x00, 0x00, 0xC0, 0xEB, 0x03, 0x61, 0xFF, 0x12,
		0xC2, 0x10, 0x00};
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, jmp_offset;
	void* zwopAddr = NULL;
	void* pAddress = NULL;
	LPVOID RemoteSectionAddr = NULL;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	zwopAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwOpenProcess");
	pAddress = (void*)hd_FindEx(hProc, zwopAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress != NULL)
	{
		RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(RemoteSectionAddr != NULL)
		{
			*(DWORD*)&pb[2] = dbgPid;
			// write the hook into the remote section
			if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			{
				jmp_offset = (DWORD)RemoteSectionAddr - ((DWORD)zwopAddr+10) - 5;
				// write the jmp to the hook in the ret of the hooked function
				*(DWORD *)&JmpToSection[1] = jmp_offset;
				
				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)zwopAddr+10), &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
					return TRUE;
			}

		}
	}

	return FALSE;
}

BOOL __stdcall hd_FindWindow(HWND hWnd, char* lpString, DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE pb[] = {0x33, 0xc0, 0xC2, 0x08, 0x00};
	HANDLE hProc;
	LPVOID FindWinAAddr = NULL, FindWinWAddr = NULL;
	DWORD lpNumberOfBytesWritten;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc != NULL)
	{
		if(SetWindowTextA(hWnd, lpString))
		{
			FindWinAAddr = (LPVOID)GetProcAddress(GetModuleHandleA("user32.dll"), "FindWindowA");
			FindWinWAddr = (LPVOID)GetProcAddress(GetModuleHandleA("user32.dll"), "FindWindowW");
			if(FindWinAAddr != NULL && FindWinWAddr)
			{
				if(WriteProcessMemory(hProc, (LPVOID)FindWinAAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
					if(WriteProcessMemory(hProc, (LPVOID)FindWinWAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
						return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL __stdcall hd_Process32Next(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x56, 0x57};
	BYTE pb[] = {0x33, 0xC0, 0xC2, 0x08, 0x00};
	void* pAddress = NULL;
	void* p32nAddr = NULL;
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten;;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	p32nAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Process32NextW");
	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 && osvi.wServicePackMajor == 0)
		pAddress = (void*)hd_FindEx(hProc, p32nAddr, 0x0100, &Pattern[2], sizeof(Pattern) - 2, &WildCard);
	else
		pAddress = (void*)hd_FindEx(hProc, p32nAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress == NULL)
		return FALSE;

	if(!WriteProcessMemory(hProc, (LPVOID)pAddress, &pb, sizeof(Pattern), &lpNumberOfBytesWritten))
		return FALSE;
	return TRUE;

}

BOOL __stdcall hd_UnhandledExceptionFilter(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0, pb = 0xeb;
	LPVOID UEFAddr = NULL;
	LPVOID UEFRemoteAddr = NULL;
	LPVOID AddrOfPatternInsideUEFVista = NULL, AddrOfPatternInsideUEF7 = NULL;
	BYTE pbXP[] = {0x90, 0x0e9};
	BYTE PatternUEFVista[] = {0x75, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x75, 0x00,
		0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x00};

	//7614FDBF   75 59            JNZ SHORT kernel32.7614FE1A
	//7614FDC1   E8 48FFFFFF      CALL kernel32.7614FD0E
	//7614FDC6   85C0             TEST EAX,EAX
	//7614FDC8   75 09            JNZ SHORT kernel32.7614FDD3
	//7614FDCA   E8 82FFFFFF      CALL kernel32.7614FD51
	//7614FDCF   85C0             TEST EAX,EAX
	//7614FDD1   74 47            JE SHORT kernel32.7614FE1A

	BYTE PatternInsideUEFVista[] = {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x7C, 0x00,
		0x83, 0x7D, 0xFC, 0x00, 0x74, 0x00, 0x33, 0xC0, 0x40};
	
	//7614FD6B   FF15 D0100B76    CALL DWORD PTR DS:[<&ntdll.NtQueryInform>; ntdll.ZwQueryInformationProcess
	//7614FD71   85C0             TEST EAX,EAX
	//7614FD73   7C 0B            JL SHORT kernel32.7614FD80
	//7614FD75   837D FC 00       CMP DWORD PTR SS:[EBP-4],0
	//7614FD79   74 05            JE SHORT kernel32.7614FD80
	//7614FD7B   33C0             XOR EAX,EAX
	//7614FD7D   40               INC EAX

	BYTE PatternUEFXP[] = {0x8D, 0x85, 0xDC, 0xFE, 0xFF, 0xFF, 0x50, 0x6A, 0x07, 0xE8,
		0x00, 0x00, 0x00, 0x00, 0x50, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00};

	//7C863EE2   8D85 DCFEFFFF    LEA EAX,DWORD PTR SS:[EBP-124]
	//7C863EE8   50               PUSH EAX
	//7C863EE9   6A 07            PUSH 7
	//7C863EEB   E8 959FFAFF      CALL kernel32.GetCurrentProcess
	//7C863EF0   50               PUSH EAX
	//7C863EF1   FF15 AC10807C    CALL DWORD PTR
	//DS:[<&ntdll.NtQueryInformationProcess>]     ;ntdll.ZwQueryInformationProcess

	BYTE UEFWin7Pattern[] = {0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x53, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83,
		0xF8, 0xFF, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F,
		0x85, 0x00, 0x00, 0x00, 0x00};
	
	//76E32B8F  ^0F84 1FF1FFFF    JE kernel32.76E31CB4
	//76E32B95   53               PUSH EBX
	//76E32B96   E8 B6010000      CALL kernel32.76E32D51
	//76E32B9B   83F8 FF          CMP EAX,-1
	//76E32B9E  ^0F84 57F0FFFF    JE kernel32.76E31BFB
	//76E32BA4   E8 C5010000      CALL kernel32.76E32D6E
	//76E32BA9   85C0             TEST EAX,EAX
	//76E32BAB  ^0F85 43F0FFFF    JNZ kernel32.76E31BF4
	
	BYTE PatternInsizeUEF7[] = {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x7C, 0x00};

	//76E32D84   FF15 3815DD76    CALL DWORD PTR DS:[<&ntdll.NtQueryInformationProcess>]                                ; ntdll.ZwQueryInformationProcess
	//76E32D8A   85C0             TEST EAX,EAX
	//76E32D8C   7C 0A            JL SHORT kernel32.76E32D98

	HANDLE hProc = NULL;
	DWORD CALL2ZwQIPInsideUEF = 0, lpNumberOfBytesRead, lpNumberOfBytesWritten;
	LPVOID lpBuffer = NULL; 
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	UEFAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "UnhandledExceptionFilter");

	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) // if XP SP1/SP2/SP3
	{
		if(osvi.wServicePackMajor == 1 || osvi.wServicePackMajor == 2 || osvi.wServicePackMajor == 3)
		{
			UEFRemoteAddr = (LPVOID)hd_FindEx(hProc, UEFAddr, 0x0100, &PatternUEFXP, sizeof(PatternUEFVista), &WildCard);

			if(UEFRemoteAddr == NULL)
				return FALSE;

			if(WriteProcessMemory(hProc, (LPVOID)((DWORD)UEFRemoteAddr+23), &pbXP, sizeof(pbXP), &lpNumberOfBytesWritten))
				return TRUE;
			
		}
		else
		{
			if(osvi.wServicePackMajor == 0) // XP SP0
			{
				UEFRemoteAddr = (LPVOID)hd_FindEx(hProc, UEFAddr, 0x0100, &PatternUEFXP[6], sizeof(PatternUEFVista) - 6, &WildCard);

				if(UEFRemoteAddr == NULL)
					return FALSE;

				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)UEFRemoteAddr+17), &pbXP, sizeof(pbXP), &lpNumberOfBytesWritten))
					return TRUE;
			}
		}
	}
	else
	{
		if(osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION) // Windows 7
		{
			UEFRemoteAddr = (LPVOID)hd_FindEx(hProc, UEFAddr, 0x0100, &UEFWin7Pattern, sizeof(UEFWin7Pattern), &WildCard);

			if(UEFRemoteAddr == NULL)
				return FALSE;

			CALL2ZwQIPInsideUEF = (DWORD)UEFRemoteAddr + 22;
			if(ReadProcessMemory(hProc, (LPVOID)CALL2ZwQIPInsideUEF, &lpBuffer, 4, &lpNumberOfBytesRead))
			{
				CALL2ZwQIPInsideUEF = CALL2ZwQIPInsideUEF - 1 + (DWORD)lpBuffer + 5;
				AddrOfPatternInsideUEF7 = (LPVOID)hd_FindEx(hProc, (LPVOID)CALL2ZwQIPInsideUEF, 0x0100, &PatternInsizeUEF7, sizeof(PatternInsizeUEF7), &WildCard);
				if(AddrOfPatternInsideUEF7 != NULL)
				{
					if(WriteProcessMemory(hProc, (LPVOID)((DWORD)AddrOfPatternInsideUEF7+8), &pb, sizeof(BYTE), &lpNumberOfBytesWritten))
						return TRUE;
				}
			}
		}
		else
		{
			UEFRemoteAddr = (LPVOID)hd_FindEx(hProc, UEFAddr, 0x0100, &PatternUEFVista, sizeof(PatternUEFVista), &WildCard);

			if(UEFRemoteAddr == NULL)
				return FALSE;

			CALL2ZwQIPInsideUEF = (DWORD)UEFRemoteAddr + 12;
			if(ReadProcessMemory(hProc, (LPVOID)CALL2ZwQIPInsideUEF, &lpBuffer, 4, &lpNumberOfBytesRead))
			{
				CALL2ZwQIPInsideUEF = CALL2ZwQIPInsideUEF - 1 + (DWORD)lpBuffer + 5;
				AddrOfPatternInsideUEFVista = (LPVOID)hd_FindEx(hProc, (LPVOID)CALL2ZwQIPInsideUEF, 0x0100, &PatternInsideUEFVista, sizeof(PatternInsideUEFVista), &WildCard);
				if(AddrOfPatternInsideUEFVista != NULL)
				{
					if(WriteProcessMemory(hProc, (LPVOID)((DWORD)AddrOfPatternInsideUEFVista+14), &pb, sizeof(BYTE), &lpNumberOfBytesWritten))
						return TRUE;
				}
			}
		}
	}
	return FALSE;
}

BOOL __stdcall hd_Module32Next(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x00, 0x56, 0x57};
	BYTE pb[] = {0x33, 0xC0, 0xC2, 0x08, 0x00};
	void* pAddress = NULL;
	void* m32nAddr = NULL;
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten;;
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&osvi, sizeof(osvi));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
		return FALSE;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	m32nAddr = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Module32NextW");
	if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 && osvi.wServicePackMajor == 0)
		pAddress = (void*)hd_FindEx(hProc, m32nAddr, 0x0100, &Pattern[2], sizeof(Pattern) - 2, &WildCard);
	else
		pAddress = (void*)hd_FindEx(hProc, m32nAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(!WriteProcessMemory(hProc, (LPVOID)pAddress, &pb, sizeof(Pattern), &lpNumberOfBytesWritten))
		return FALSE;
	return TRUE;
}

BOOL __stdcall hd_ZwQueryObject(DWORD pid)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	BYTE WildCard = 0;
	BYTE Pattern[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0x00};//, 0xff, 0x12}; 
	BYTE JmpToSection[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	BYTE pb[] = {0xFF, 0x12, 0x60, 0x83, 0x7C, 0x24, 0x28, 0x03, 0x75, 0x0C, 0x8B, 0x7C, 0x24,
		0x2C, 0x8B, 0x4C, 0x24, 0x30, 0x33, 0xC0, 0xF3, 0xAA, 0x61, 0xC2, 0x14, 0x00};
	HANDLE hProc = NULL;
	DWORD lpNumberOfBytesWritten, jmp_offset;
	void* zwqoAddr = NULL;
	void* pAddress = NULL;
	LPVOID RemoteSectionAddr = NULL;

	hProc = hd_GetProcHandleByPid(pid);
	if(hProc == NULL)
		return FALSE;

	zwqoAddr = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryObject");
	pAddress = (void*)hd_FindEx(hProc, zwqoAddr, 0x0100, &Pattern, sizeof(Pattern), &WildCard);

	if(pAddress != NULL)
	{
		RemoteSectionAddr = VirtualAllocEx(hProc, NULL, 0x0100, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(RemoteSectionAddr != NULL)
		{
			// write the hook into the remote section
			if(WriteProcessMemory(hProc, (LPVOID)RemoteSectionAddr, &pb, sizeof(pb), &lpNumberOfBytesWritten))
			{
				jmp_offset = (DWORD)RemoteSectionAddr - ((DWORD)zwqoAddr+10) - 5;
				// write the jmp to the hook in the ret of the hooked function
				*(DWORD *)&JmpToSection[1] = jmp_offset;
				
				if(WriteProcessMemory(hProc, (LPVOID)((DWORD)zwqoAddr+10), &JmpToSection, sizeof(JmpToSection), &lpNumberOfBytesWritten))
					return TRUE;
			}

		}
	}

	return FALSE;
}

BOOL __stdcall hd_DllInjector(DWORD ProcessId, char* DLLLibPath, bool WaitForResponse)
{
	/*
		Description: 
		Syntax: 
		Parameters:
		Return value:
	*/

	HANDLE hThread, hProcess;
	void* pLibRemote;
	DWORD hLibModule;
	HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");

	hProcess = hd_GetProcHandleByPid(ProcessId);
	pLibRemote = VirtualAllocEx(hProcess, NULL, strlen(DLLLibPath),
								MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	if(WriteProcessMemory(hProcess, pLibRemote, DLLLibPath, strlen(DLLLibPath), NULL))
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32,
																				"LoadLibraryA"),
									pLibRemote, 0, NULL);

		if(hThread != NULL)
		{
			if(WaitForResponse)
				WaitForSingleObject(hThread, INFINITE);
				GetExitCodeThread(hThread, &hLibModule);
		}
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pLibRemote, sizeof(DLLLibPath), MEM_RELEASE);
		CloseHandle(hProcess);
		return TRUE;
	}
	return FALSE;
}
