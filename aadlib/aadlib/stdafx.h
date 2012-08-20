/*
 $Id: stdafx.h 22 2012-02-19 05:59:43Z crackinglandia $ 

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
*/

#pragma once

#include <windows.h>
#include "targetver.h"

#ifndef VER_SUITE_WH_SERVER
#define VER_SUITE_WH_SERVER 0x00008000
#endif

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers

#define PROCESS_DEBUG_PORT 7

typedef DWORD (WINAPI *lpfNtQueryInformationProcess) (HANDLE, DWORD, LPVOID, DWORD, LPVOID);
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0,
	ThreadTimes = 1, 
	ThreadPriority = 2, 
	ThreadBasePriority = 3, 
	ThreadAffinityMask = 4, 
	ThreadImpersonateToken = 5, 
	ThreadDescriptorTableEntry = 6, 
	ThreadEnableAligmentFaultFixup = 7, 
	ThreadEventPair = 8, 
	ThreadQuerySetWin32StartAddress = 9, 
	ThreadZeroTlsCell = 10, 
	ThreadPerformanceCount = 11, 
	ThreadAmILastThread = 12, 
	ThreadIdealProcessor = 13, 
	ThreadPriorityBoost = 14, 
	ThreadSetTlsArrayAddress = 15, 
	ThreadIsIoPending = 16, 
	ThreadHideFromDebugger = 17
} THREADINFOCLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7, 
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessDebugFlags = 0x1f,
	ProcessDebugObjectHandle = 0x1e
} PROCESSINFOCLASS;

typedef enum _OSFAMILY{
	Windows2000 = 0, 
	WindowsHomeServer, 
	WindowsXP,
	WindowsXP64,
	Windows2003, 
	Windows2003R2, 
	WindowsVista, 
	Windows7, 
	Windows2008, 
	Windows2008R2,
	UnknownOS = -1
} OSFAMILY;

typedef enum _SERVICEPACK{
	SP0 = 0, 
	SP1, 
	SP2, 
	SP3, 
	SP4,
	UnknownSP = -1
} SERVICEPACK;