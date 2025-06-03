/* 
#include <Windows.h>
#include <winerror.h>
#include <stdio.h>

int main()
{
    DWORD pid = GetCurrentProcessId();  // Получаем PID текущего процесса
    printf("pid = %d\n", pid);
    int i = 0;
    while (true)
    {
        printf("Processing - %d\n", i++);
        Sleep(1000);
    }
    return 0;
}
*/

#include <Windows.h>
#include <winerror.h>
#include <stdio.h>
#include <string.h>

#define STOP_ARG "xakep"

BOOL CreateProcessWithBlockDllPolicy(LPSTR lpProcessPath, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {
    STARTUPINFOEXA SiEx = { 0 };
    PROCESS_INFORMATION Pi = { 0 };
    SIZE_T sAttrSize = 0;

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Получаем размер списка атрибутов
    InitializeProcThreadAttributeList(NULL, 1, 0, &sAttrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);
    if (!pAttrList) {
        printf("[!] HeapAlloc failed\n");
        return FALSE;
    }

    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &sAttrSize)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    // Устанавливаем политику блокировки загрузки DLL
    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(dwPolicy), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }

    SiEx.lpAttributeList = pAttrList;

    BOOL bRet = CreateProcessA(
        NULL,
        lpProcessPath,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &SiEx.StartupInfo,
        &Pi);

    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);

    if (!bRet) {
        printf("[!] CreateProcessA Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return TRUE;
}

int main(int argc, char* argv[]) {
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL, hThread = NULL;

    if (argc == 2 && strcmp(argv[1], STOP_ARG) == 0) {
        printf("[+] Process Is Now Protected With The Block Dll Policy\n");

        DWORD pid = GetCurrentProcessId();
        printf("pid = %d\n", pid);

        int i = 0;
        while (true) {
            printf("Processing - %d\n", i++);
            Sleep(1000);
        }


    }
    else {
        printf("[!] Local Process Is Not Protected With The Block Dll Policy\n");

        CHAR pcFilename[MAX_PATH];
        if (!GetModuleFileNameA(NULL, pcFilename, MAX_PATH)) {
            printf("[!] GetModuleFileNameA Failed With Error: %d\n", GetLastError());
            return -1;
        }

        // Формируем командную строку: путь_к_файлу + " xakep"
        size_t len = strlen(pcFilename) + strlen(STOP_ARG) + 2;
        CHAR* pcCmdLine = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
        if (!pcCmdLine) {
            printf("[!] HeapAlloc failed\n");
            return -1;
        }

        sprintf_s(pcCmdLine, len, "%s %s", pcFilename, STOP_ARG);

        if (!CreateProcessWithBlockDllPolicy(pcCmdLine, &dwProcessId, &hProcess, &hThread)) {
            HeapFree(GetProcessHeap(), 0, pcCmdLine);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcCmdLine);

        printf("[i] Process Created With Pid %d\n", dwProcessId);

        // Завершаем текущий процесс, чтобы осталась только защищённая копия
        return 0;
    }

    return 0;
}
