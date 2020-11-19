// DllRemoteInjection.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

BOOL DllRemoteInjection(
	DWORD dwProcessID,  // Dll注入的目标进程 ID
	PCHAR szDllName     // Dll路径名称
);
BOOL GetProcessIdByName(PCHAR szProcessName, LPDWORD lpPID);

int main(int argc, char* argv[], char* envp[])
{
	BOOL b_success;
	if (argc != 3)
	{
		printf("The Program Usage: DllRemoteInjection [PID] [DLLname]\n\n");
		return 0;
	}
	DWORD dwProcessID;
	b_success = GetProcessIdByName(argv[1], &dwProcessID);
	if (!b_success)
	{
		printf("GetProcessId failed.\n");
		return -1;
	}

	b_success = DllRemoteInjection(dwProcessID, argv[2]);
	if (b_success)
		printf("Dll injection succeed.\n");
	else
	{
		printf("Dll injection failed.\n");
		return -1;
	}
	return 0;
}

BOOL DllRemoteInjection(DWORD dwProcessID, PCHAR szDllName)
{
	HANDLE    hProcess;
	HINSTANCE hModule;
	SIZE_T    dwLenth;
	LPVOID    lpAllocAddr;
	BOOL      bWritable;
	PDWORD    dwLoadLibAddr;
	HANDLE    hThread;

	// 1. 获取进程句柄
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hProcess == NULL)
	{
		printf("Open Process Error!\n");
		return FALSE;
	}
	// 2. 计算DLL路径名字长度，加上结尾的‘0’
	dwLenth = strlen(szDllName) + 1;
	// 3. 在目标进程分配内存
	lpAllocAddr = VirtualAllocEx(hProcess, NULL, dwLenth, MEM_COMMIT, PAGE_READWRITE);
	if (lpAllocAddr == NULL)
	{
		printf("Virtual Memory Alloc Failed!\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	// 4. 将待注入Dll的名称写入目标进程的内存
	bWritable = WriteProcessMemory(hProcess, lpAllocAddr, szDllName, dwLenth, NULL);
	if (bWritable == 0)
	{
		printf("WriteProcessMemory() Failed!\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	// 5. 获取共用模块Kernel32.dll的模块句柄
	hModule = GetModuleHandleA("Kernel32.dll");
	if (hModule == NULL)
	{
		printf("GetModuleHandleA() Failed!\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	// 6. 获取LoadLibraryA函数地址
	dwLoadLibAddr = (DWORD*)GetProcAddress(hModule, "LoadLibraryA");
	if (dwLoadLibAddr == NULL)
	{
		printf("GetProcAddress(hModule, \"LoadLibraryA\") Failed!\n");
		CloseHandle(hProcess);
		CloseHandle(hModule);
		return FALSE;
	}
	// 7. 创建远程线程，加载DLL
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwLoadLibAddr, lpAllocAddr, 0, NULL);
	if (hThread == NULL)
	{
		printf("CreateRemoteThread Failed!\n");
		CloseHandle(hProcess);
		CloseHandle(hModule);
		return FALSE;
	}

	// 8. 关闭进程句柄
	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hModule);
	return TRUE;
}

BOOL GetProcessIdByName(PCHAR szProcessName, LPDWORD lpPID)
{
	HANDLE         hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return (FALSE);
	if (Process32First(hProcessSnap, &pe32))
	{
		// 这边有一个点就是宽字符的问题，解决方法如下，再VC6上编译就没有此问题
		TCHAR temp[260] = { 0 };
		int lenth = strlen(szProcessName) + 1;
		for (int i = 0; i < lenth; i++)
			temp[i] = szProcessName[i];
		if (!wcscmp((pe32.szExeFile), temp))
		{
			*lpPID = pe32.th32ProcessID;
			return TRUE;
		}
		do {
			if (!wcscmp((pe32.szExeFile), temp))
			{
				*lpPID = pe32.th32ProcessID;
				return TRUE;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
		return FALSE;

	CloseHandle(hProcessSnap);
	return FALSE;
}
