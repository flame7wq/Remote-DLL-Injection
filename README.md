# Remote-DLL-Injection
Remote DLL Injection

远程进程注入思路
1. 根据进程名遍历进程快照找到进程ID
2. 用 PID 获取进程句柄
3. 计算DLL路径名字长度，加上结尾的‘0’
4. 在目标进程分配内存
5. 将待注入Dll的名称写入目标进程的内存
6. 获取共用模块Kernel32.dll的模块句柄
7. 获取LoadLibraryA函数地址
8. 创建远程线程，加载DLL
9. 关闭进程句柄


关键 WINDOWS API
* CreateToolhelp32Snapshot()
* OpenProcess()
* VirtualAllocEx()
* WriteProcessMemory()
* GetModuleHandleA()
* GetProcAddress()
* CreateRemoteThread()


**本质思想：利用创建远程线程注入DLL，并利用 DLLMain() 函数的性质**
