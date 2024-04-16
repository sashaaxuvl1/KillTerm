#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <Shellapi.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "ntdll.lib") // Добавленная директива для библиотеки ntdll.lib

bool IsUserAnAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b;

    b = AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);
    if (!b) {
        return false;
    }

    if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
        b = false;
    }

    FreeSid(AdministratorsGroup);
    return b != 0;
}

bool runAsAdmin() {
    wchar_t moduleName[MAX_PATH];
    GetModuleFileName(NULL, moduleName, MAX_PATH);

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = moduleName;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteEx(&sei)) {
        DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            std::cerr << "User refused to allow elevated privileges." << std::endl;
        }
        else {
            std::cerr << "Failed to elevate privileges. Error code: " << error << std::endl;
        }
        return false;
    }

    return true;
}

bool enableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

void listProcesses(bool fullList) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed." << std::endl;
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful.
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Process32First failed." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    std::cout << "Process ID\t| Process Name\t|" << std::endl;

    // Iterate through all processes
    do {
        if (fullList) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                WCHAR szProcessName[MAX_PATH] = L"";
                DWORD dwSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, szProcessName, &dwSize)) {
                    PROCESS_MEMORY_COUNTERS_EX pmc;
                    if (GetProcessMemoryInfo(hProcess, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                        std::wcout << pe32.th32ProcessID << "\t\t| " << szProcessName << "\t\t| " << pmc.WorkingSetSize / (1024 * 1024) << std::endl;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        else {
            std::wcout << pe32.th32ProcessID << "\t\t| " << pe32.szExeFile << std::endl;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

void killProcessByPath(const std::wstring& processPath) {
    if (!enableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return;
    }

    DWORD processes[1024], processesSize, processCount;
    if (!EnumProcesses(processes, sizeof(processes), &processesSize)) {
        std::cerr << "Failed to enumerate processes." << std::endl;
        return;
    }

    processCount = processesSize / sizeof(DWORD);
    for (DWORD i = 0; i < processCount; ++i) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processes[i]);
        if (hProcess) {
            WCHAR szProcessName[MAX_PATH] = L"";
            DWORD dwSize = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, szProcessName, &dwSize)) {
                if (std::wstring(szProcessName) == processPath) {
                    TerminateProcess(hProcess, 0);
                    std::wcout << L"Process terminated successfully: " << szProcessName << std::endl;
                }
            }
            CloseHandle(hProcess);
        }
    }
}

void killProcessByName(const std::wstring& processName) {
    if (!enableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return;
    }

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed." << std::endl;
        return;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful.
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Process32First failed." << std::endl;
        CloseHandle(hProcessSnap);
        return;
    }

    // Iterate through all processes
    do {
        std::wstring szProcessName(pe32.szExeFile);
        if (szProcessName == processName) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                TerminateProcess(hProcess, 0);
                std::wcout << L"Process terminated successfully: " << szProcessName << std::endl;
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

void killProcessByPID(DWORD processId) {
    if (!enableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process." << std::endl;
        return;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process." << std::endl;
    }
    else {
        std::cout << "Process terminated successfully." << std::endl;
    }

    CloseHandle(hProcess);
}

int main() {
    if (!IsUserAnAdmin()) {
        std::cout << "This program requires administrator privileges to run properly." << std::endl;
        std::cout << "Attempting to elevate privileges..." << std::endl;
        if (!runAsAdmin()) {
            return 1;
        }
        return 0; // Exiting as the program will be relaunched with admin privileges.
    }

    std::cout << "Do you want to see the full path or just the name of the processes?" << std::endl;
    std::cout << "Enter 'full' to see the full path or 'name' to see only the name: ";
    std::string choice;
    std::cin >> choice;

    bool fullList;
    if (choice == "full") {
        fullList = true;
    }
    else if (choice == "name") {
        fullList = false;
    }
    else {
        std::cerr << "Invalid choice." << std::endl;
        return 1;
    }

    listProcesses(fullList);

    std::cout << "Do you want to kill any process?" << std::endl;
    std::cout << "Enter 'path' to kill by process path, 'pid' to kill by PID, or 'name' to kill by process name: ";
    std::string killChoice;
    std::cin >> killChoice;

    if (killChoice == "path") {
        std::wstring processPath;
        std::wcout << L"Enter the full path of the process to kill: ";
        std::wcin >> processPath;
        killProcessByPath(processPath);
    }
    else if (killChoice == "pid") {
        std::cout << "Enter the PID of the process to kill: ";
        DWORD processId;
        std::cin >> processId;
        killProcessByPID(processId);
    }
    else if (killChoice == "name") {
        std::wstring processName;
        std::wcout << L"Enter the name of the process to kill (with .exe): ";
        std::wcin >> processName;
        killProcessByName(processName);
    }
    else {
        std::cerr << "Invalid choice." << std::endl;
        return 1;
    }

    return 0;
}
