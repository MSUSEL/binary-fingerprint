# DLL's and API calls
Below is a list that I've been compiling that list DLLs associated with certain things and are used by malware.  

A - means Ascii  
W - means Unicode  
Ex - means extended  

## Important DLL's for programs
	1. NTDLL.DLL
	2. KERNEL32.DLL
	3. KERNELBASE.DLL
	4. GID32.DLL
	5. USER32.DLL
	6. COMCTL32.DLL
	7. ADVAPI32.DLL
	8. OLE32.DLL
	9. NETAPI32.DLL
	10. COMDLG32.DLL
	11. WS2_32.DLL
	12. WININET.DLL

## File Operations
	1. CreateFile
	2. WriteFile
	3. ReadFile
	4. SetFilePointer
	5. DeleteFile
	6. CloseFile

## Registry
	1. RegCreateKey
	2. RegDeleteKey
	3. RegSetValue

## Memory
	1. VirtualAlloc
	2. VirtualProtect
	3. NtCreateSection
	4. WriteProcessMemory
	5. NtMapViewOfSection

## Processes and Threads
	1. CreateProcess
	2. ExitProcess
	3. CreateRemoteThread
	4. CreateThread
	5. GetThreadContext
	6. SetThreadContext
	7. TerminateProcess
	8. CreateProcessInternalW

## DLL Operations
	1. LoadLibrary
	2. GetProcAddress

## Service Registration
	1. OpenSCManager
	2. CreateService
	3. OpenService
	4. ChangeServiceConfig2W
	5. StartService

## Mutexs
	1. CreateMutex
	2. OpenMutex
	
## Code Injection
Step 1:  
1. CreateProcessA
2. CreateProcessW
3. CreateProcessInternalW
4. CreateProcessInternalA
5. Process32Next
6. Process32First
7. CreateToolhelp32Snapshot

Step 2:  
1. OpenProcess
2. VirtualAllocEx
3. LookupPrivilegeValue	
4. AdjustTokenPrivileges
5. OpenProcessToken
6. VirtualProtect

Step 3:  
1. WriteProcessMemory
2. NtUnmapViewOfSection
3. NtCreateSection
4. NtMapViewOfSection

Step 4:  
1. QueueUserAPC
2. SuspendThread
3. ResumeThread
4. CreateRemoteThread
5. RtlCreateUserThread
6. NtCreateThreadEx
7. GetThreadContext
8. SetThreadContext

## Data Stealing 
**user32.dll**  
1. TranslateMessage
2. DispatchMessage
3. getAsyncKeyState
4. GetKeyBoardState
5. PeekMessage
6. GetMessage

## Network Communication
**ws2_32.dll**
1. gethostbyname
2. Getaddrinfo
3. Send
4. Connect
5. WSASend

**wsock32.dll**
1. send
2. connect

**Wininet.dll**
1. InternetConnectA
2. InternetConnectW

## Intercept Banking
**wininet.dll (used for internet explorer)**  
1. internetConnectA
2. InternetConnectW
3. HttpOpenRequestA
4. HttpOpenRequestW
5. HttpSendRequestA
6. HttpSendRequestW
7. HttpSendRequestExA
8. HttpSendRequestExW
9. InternetReadFile
10. InternetReadFileExA
	
**spr4.dll (used for firefox)**  
1. PR_OpenTCPSocket
2. PR_Connect
3. PR_Close
4. PR_Write
5. PR_Read

**chrome.dll (used for chrome)**  
1. ssl_read
2. ssl_write

## Key Logging
	1. GetWindowThreadProcessId
	2. CallNextHookEx
	3. GetMessage
	4. GetKeyboardState
	5. GetSystemMetrics
	6. TranslateMessage
	7. GetAsyncKeyState
	8. DispatchMessage
	9. SetWindowsHookEx
