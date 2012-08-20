// $Id: aadlib.h 19 2010-12-02 15:44:48Z nahuelriva $
#pragma comment(lib, "aadlib.lib")

// Functions that do the magic ...
bool __stdcall hd_GetTickCount(DWORD pid);
bool __stdcall hd_HeapFlagsOnPEB(DWORD pid);
bool __stdcall hd_NtGlobalFlags(DWORD pid);
bool __stdcall hd_IsDebuggerPresent(DWORD pid);
bool __stdcall hd_HookZwQueryInformationProcess(DWORD pid);
bool __stdcall hd_HookZwSetInformationThread(DWORD pid);
bool __stdcall hd_HookOutputDebugString(DWORD pid);
bool __stdcall hd_ZwQueryObject(DWORD pid);
bool __stdcall hd_ZwOpenProcess(DWORD DebugeePid, DWORD DbgPid);
bool __stdcall hd_Module32Next(DWORD pid);
bool __stdcall hd_Process32Next(DWORD pid);
bool __stdcall hd_BlockInput(DWORD pid);
bool __stdcall hd_SuspendThread(DWORD pid);
bool __stdcall hd_TerminateProcess(DWORD pid);
bool __stdcall hd_FindWindow(HWND hWnd, char* lpString, DWORD pid);
bool __stdcall hd_UnhandledExceptionFilter(DWORD pid);
bool __stdcall hd_ZwQuerySystemInformation(DWORD pid);

// Auxiliary functions
HANDLE __stdcall hd_GetProcHandleByPid(DWORD pid);
DWORD __stdcall hd_GetProcPidByHandle(HANDLE pHandle);
void* __stdcall hd_GetPEBAddress(DWORD pid);
bool __stdcall hd_DllInjector(DWORD ProcessId, char* DLLLibPath, bool WaitForResponse);
