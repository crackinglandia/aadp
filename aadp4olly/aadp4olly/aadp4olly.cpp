// $Id: aadp4olly.cpp 19 2010-12-02 15:44:48Z nahuelriva $
/*
 Anti-Anti-Debugging Plugin for Ollydbg v0.2 - LGPL 3.0

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
 Date: -
 @: nahuelriva@gmail.com
 Blog: http://crackinglandia.blogspot.com
 Twitter: @crackinglandia

*/

#include "aadp4olly.h"

static HINSTANCE hinst;            
static HWND      hwmain;
static HWND      hwcmd;  

HWND hwPluginWin;

int Flag = 0;

bool	bIsDbgPresent = FALSE, 
		bNtGlobalFlags = FALSE, 
		bHeapFlags = FALSE, 
		bODS = FALSE, 
		bGetTickCount = FALSE, 
		bZwSIT = FALSE, 
		bZwQIP = FALSE,
		bSuspendThread = FALSE,
		bUEF = FALSE,
		bModule32Next = FALSE,
		bProcess32Next = FALSE,
		bFindWindow = FALSE,
		bZwQueryObject = FALSE,
		bZwOpenProcess = FALSE,
		bTerminateProcess = FALSE,
		bBlockInput = FALSE,
		bZWQSI = FALSE;

void CheckForOptions(void)
{
	HMODULE hModule;

	hModule = GetModuleHandleA("aadp4olly.dll");
	
	// Check for IsDebuggerPresent
	if(Pluginreadintfromini(hModule, "hd_IsDebuggerPresent", CW_USEDEFAULT) == 1)
	{
			CheckDlgButton(hwPluginWin, IDC_ISDBGPRESENT, BST_CHECKED);
			bIsDbgPresent = TRUE;
	}
	else
	{
			CheckDlgButton(hwPluginWin, IDC_ISDBGPRESENT, BST_UNCHECKED);
			bIsDbgPresent = FALSE;
	}

	// Check for NtGlobalFlags
	if(Pluginreadintfromini(hModule, "hd_NtGlobalFlags", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_NTGLOBALFLAGS, BST_CHECKED);
		bNtGlobalFlags = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_NTGLOBALFLAGS, BST_UNCHECKED);
		bNtGlobalFlags = FALSE;
	}

	// Check for HeapFlags
	if(Pluginreadintfromini(hModule, "hd_HeapFlags", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_HEAPFLAGS, BST_CHECKED);
		bHeapFlags = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_HEAPFLAGS, BST_UNCHECKED);
		bHeapFlags = FALSE;
	}

	// Check for ZwSetInformationThread
	if(Pluginreadintfromini(hModule, "hd_ZwSetInformationThread", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ZWSIT, BST_CHECKED);
		bZwSIT = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ZWSIT, BST_UNCHECKED);
		bZwSIT = FALSE;
	}

	// Check for ZwQueryInformationProcess
	if(Pluginreadintfromini(hModule, "hd_ZwQueryInformationProcess", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQIP, BST_CHECKED);
		bZwQIP = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQIP, BST_UNCHECKED);
		bZwQIP = FALSE;
	}

	// Check for GetTickCount
	if(Pluginreadintfromini(hModule, "hd_GetTickCount", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_GETTICKCOUNT, BST_CHECKED);
		bGetTickCount = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_GETTICKCOUNT, BST_UNCHECKED);
		bGetTickCount = FALSE;
	}

	// Check for OutputDebugString
	if(Pluginreadintfromini(hModule, "hd_OutputDebugString", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ODS, BST_CHECKED);
		bODS = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ODS, BST_UNCHECKED);
		bODS = FALSE;
	}

	// Check for ZwQueryObject
	if(Pluginreadintfromini(hModule, "hd_ZwQueryObject", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQUERYOBJECT, BST_CHECKED);
		bZwQueryObject = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQUERYOBJECT, BST_UNCHECKED);
		bZwQueryObject = FALSE;
	}

	// Check for ZwOpenProcess
	if(Pluginreadintfromini(hModule, "hd_ZwOpenProcess", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ZWOPENPROCESS, BST_CHECKED);
		bZwOpenProcess = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ZWOPENPROCESS, BST_UNCHECKED);
		bZwOpenProcess = FALSE;
	}

	// Check for FindWindow
	if(Pluginreadintfromini(hModule, "hd_FindWindow", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_FINDWINDOW, BST_CHECKED);
		bFindWindow = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_FINDWINDOW, BST_UNCHECKED);
		bFindWindow = FALSE;
	}

	// Check for Module32Next
	if(Pluginreadintfromini(hModule, "hd_Module32Next", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_MODULE32NEXT, BST_CHECKED);
		bModule32Next = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_MODULE32NEXT, BST_UNCHECKED);
		bModule32Next = FALSE;
	}

	// Check for Process32Next
	if(Pluginreadintfromini(hModule, "hd_Process32Next", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_PROCESS32NEXT, BST_CHECKED);
		bProcess32Next = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_PROCESS32NEXT, BST_UNCHECKED);
		bProcess32Next = FALSE;
	}

	// Check for UnhandledExceptionFilter
	if(Pluginreadintfromini(hModule, "hd_UnhandledExceptionFilter", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_UEF, BST_CHECKED);
		bUEF = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_UEF, BST_UNCHECKED);
		bUEF = FALSE;
	}

	// Check for SuspendThread
	if(Pluginreadintfromini(hModule, "hd_SuspendThread", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_SUSPENDTHREAD, BST_CHECKED);
		bSuspendThread = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_SUSPENDTHREAD, BST_UNCHECKED);
		bSuspendThread = FALSE;
	}

	// Check for TerminateProcess
	if(Pluginreadintfromini(hModule, "hd_TerminateProcess", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_TERMINATEPROCESS, BST_CHECKED);
		bTerminateProcess = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_TERMINATEPROCESS, BST_UNCHECKED);
		bTerminateProcess = FALSE;
	}

	// Check for BlockInput
	if(Pluginreadintfromini(hModule, "hd_BlockInput", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_BLOCKINPUT, BST_CHECKED);
		bBlockInput = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_BLOCKINPUT, BST_UNCHECKED);
		bBlockInput = FALSE;
	}

	if(Pluginreadintfromini(hModule, "hd_QuerySystemInformation", CW_USEDEFAULT) == 1)
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQSI, BST_CHECKED);
		bZWQSI = TRUE;
	}
	else
	{
		CheckDlgButton(hwPluginWin, IDC_ZWQSI, BST_UNCHECKED);
		bZWQSI = FALSE;
	}

}

void CheckForBSTChecked(HWND hw, DWORD ID, char* Key)
{
	if(IsDlgButtonChecked(hw, ID) == BST_CHECKED)
	{
		if(!Pluginwriteinttoini(GetModuleHandleA("aadp4olly.dll"), Key, 1))
			Addtolist(0, HIGHLIGHTED,"Could't write config to Ollydbg.ini");
	}
	else
	{
		if(!Pluginwriteinttoini(GetModuleHandleA("aadp4olly.dll"), Key, 0))
			Addtolist(0, HIGHLIGHTED,"Could't write config to Ollydbg.ini");
	}

}

void SetOptions(void)
{
	CheckForBSTChecked(hwPluginWin, IDC_ISDBGPRESENT, "hd_IsDebuggerPresent");
	CheckForBSTChecked(hwPluginWin, IDC_ZWSIT, "hd_ZwSetInformationThread");
	CheckForBSTChecked(hwPluginWin, IDC_ZWQIP, "hd_ZwQueryInformationProcess");
	CheckForBSTChecked(hwPluginWin, IDC_NTGLOBALFLAGS, "hd_NtGlobalFlags");
	CheckForBSTChecked(hwPluginWin, IDC_HEAPFLAGS, "hd_HeapFlags");
	CheckForBSTChecked(hwPluginWin, IDC_ODS, "hd_OutputDebugString");
	CheckForBSTChecked(hwPluginWin, IDC_GETTICKCOUNT, "hd_GetTickCount");
	CheckForBSTChecked(hwPluginWin, IDC_ZWQUERYOBJECT, "hd_ZwQueryObject");
	CheckForBSTChecked(hwPluginWin, IDC_ZWOPENPROCESS, "hd_ZwOpenProcess");
	CheckForBSTChecked(hwPluginWin, IDC_FINDWINDOW, "hd_FindWindow");
	CheckForBSTChecked(hwPluginWin, IDC_UEF, "hd_UnhandledExceptionFilter");
	CheckForBSTChecked(hwPluginWin, IDC_SUSPENDTHREAD, "hd_SuspendThread");
	CheckForBSTChecked(hwPluginWin, IDC_BLOCKINPUT, "hd_BlockInput");
	CheckForBSTChecked(hwPluginWin, IDC_TERMINATEPROCESS, "hd_TerminateProcess");
	CheckForBSTChecked(hwPluginWin, IDC_PROCESS32NEXT, "hd_Process32Next");
	CheckForBSTChecked(hwPluginWin, IDC_MODULE32NEXT, "hd_Module32Next");
	CheckForBSTChecked(hwPluginWin, IDC_ZWQSI, "hd_QuerySystemInformation");
}

LRESULT CALLBACK aadp4Ollyproc(HWND hw,UINT msg,WPARAM wp,LPARAM lp) {
  hwPluginWin = hw;

  switch(msg)
  {
  case WM_INITDIALOG:
	CheckForOptions();
    return 1;
  case WM_COMMAND:
    switch(wp)
    {
    case IDOK:
		SetOptions();
		EndDialog(hw, 0);
		return 0;
    case IDCANCEL:
		EndDialog(hw, 0);
    }
  }
  return 0;
}

static void Createaadp4ollywindow(void) {
  InitCommonControls();
  DialogBoxParamA(hinst, (LPCSTR)IDD_AADP4OLLY, hwmain, (DLGPROC)aadp4Ollyproc, 0);

}

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH)
		hinst = hi;
	return 1;
};

extc int _export cdecl ODBG_Plugindata(char shortname[32]) {
  strcpy_s(shortname, sizeof("aadp4olly"), "aadp4olly");
  return PLUGIN_VERSION;
};

extc int _export cdecl ODBG_Plugininit(int ollydbgversion,HWND hw,ulong *features){
	
	hwmain = hw;

	if (ollydbgversion < PLUGIN_VERSION)
		return -1;

	Addtolist(0,0,"aadp4plugin v0.2");
	Addtolist(0,-1,"  Written by +NCR/CRC! [ReVeRsEr]");

	CheckForOptions();
	return 0;

}

extc void _export cdecl ODBG_Pluginmainloop(DEBUG_EVENT *debugevent) {
	t_status status;
	DWORD pid = -1;

	status = Getstatus();

	// Si hay un proceso cargado y ese proceso esta detenido ...
	if(status != STAT_NONE && status == STAT_STOPPED)
	{
		// Incremento un flag
		Flag++;
		if(Flag == 1) // es la primera vez que pasa? ...
		{
			// esta el checkbox de IsDebuggerPresent activado? ...
			pid = _Plugingetvalue(VAL_PROCESSID);
			if(bIsDbgPresent)
			{
				// entonces, patcheo el BeingDebugged flag
				if(!hd_IsDebuggerPresent(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch BeingDebugged flag on PEB :(");
			}
			if(bNtGlobalFlags)
			{
				if(!hd_NtGlobalFlags(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch NtGlobalFlags flag on PEB :(");
			}
			if(bHeapFlags)
			{
				if(!hd_HeapFlagsOnPEB(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch HeapFlags flag on PEB :(");
			}

			if(bZwQIP)
			{	
				if(!hd_HookZwQueryInformationProcess(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch ZwQueryInformationProcess :(");
			}

			if(bZwSIT)
			{
				if(!hd_HookZwSetInformationThread(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch ZwSetInformationThread :(");
			}

			if(bGetTickCount)
			{
				if(!hd_GetTickCount(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch GetTickCount :(");
			}

			if(bODS)
			{
				if(!hd_HookOutputDebugString(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch OutputDebugString :(");
			}

			if(bZwQueryObject)
			{
				if(!hd_ZwQueryObject(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch ZwQueryObject :(");
			}

			if(bZwOpenProcess)
			{
				if(!hd_ZwOpenProcess(pid, GetCurrentProcessId()))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch ZwOpenProcess :(");
			}

			if(bFindWindow)
			{
				if(!hd_FindWindow((HWND)_Plugingetvalue(VAL_HWMAIN), "", pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch FindWindow :(");
			}

			if(bUEF)
			{
				if(!hd_UnhandledExceptionFilter(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch UnhandledExceptionFilter :(");
			}

			if(bSuspendThread)
			{
				if(!hd_SuspendThread(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch SuspendThread :(");
			}

			if(bBlockInput)
			{
				if(!hd_BlockInput(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch BlockInput :(");
			}

			if(bTerminateProcess)
			{
				if(!hd_TerminateProcess(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch TerminateProcess :(");
			}

			if(bProcess32Next)
			{
				if(!hd_Process32Next(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch Process32Next :(");
			}

			if(bModule32Next)
			{
				if(!hd_Module32Next(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch Module32Next :(");
			}

			if(bZWQSI)
			{
				if(!hd_ZwQuerySystemInformation(pid))
					Addtolist(0, HIGHLIGHTED, "aadp4olly error: Can't patch ZwQuerySystemInformation :(");
			}
		}
	}
}

extc int _export cdecl ODBG_Pluginmenu(int origin,char data[4096],void *item) {
	char str[] = "0 &Options\tAlt+Q|1 &Help,2 &About";
	if (origin!=PM_MAIN)
		return 0;
	strcpy_s(data, 4096, str);
	return 1;
}

extc int _export cdecl ODBG_Pluginshortcut(int origin,int ctrl,int alt,int shift,int key,void *item) {
  if(origin == PM_MAIN)
  {
	  if(key==VK_ESCAPE)
		  EndDialog(hwPluginWin, 0);

	  if (ctrl==0 && alt==1 && shift==0 && key=='Q') 
	  {
		Createaadp4ollywindow();
		CheckForOptions();
		return 1;
	  }                   
  }
  return 0;
};

extc void _export cdecl ODBG_Pluginaction(int origin,int action,void *item) {
  if (origin!=PM_MAIN)
    return;

  switch (action) {
    case 0:
      Createaadp4ollywindow();
	  CheckForOptions();
      break;
    case 1:
		ShellExecuteA(NULL, "open", "http://code.google.com/p/aadp", 0, 0, SW_SHOWNORMAL);
      break;
    case 2:
      MessageBoxA(hwmain,
		  "aadp4olly plugin v0.2\nWritten by +NCR/CRC! [ReVeRsEr]",
        "aadp4olly", MB_OK|MB_ICONINFORMATION);
      break;
    default: break;
  };
}

extc int _export cdecl ODBG_Pluginclose(void) {
	return 0;
}

extc void _export cdecl ODBG_Pluginreset(void) {
	Flag = 0;
	CheckForOptions();
}
