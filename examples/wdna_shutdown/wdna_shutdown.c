#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

LPCTSTR SlotName = TEXT("\\\\.\\mailslot\\steadybit\\wdna");

BOOL WriteSlot(HANDLE hSlot, LPCTSTR lpszMessage)
{
    BOOL fResult;
    DWORD cbWritten;

    fResult = WriteFile(hSlot,
        lpszMessage,
        (DWORD)(lstrlen(lpszMessage) + 1) * sizeof(TCHAR),
        &cbWritten,
        (LPOVERLAPPED)NULL);

    if (!fResult)
    {
        printf("error: shutdown execute failed with %d.\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL IsProcessRunning(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("error: unable to get the system snapshot.\n");
        return FALSE;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return TRUE;  
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return FALSE;
}

int main()
{
    HANDLE hFile;

    hFile = CreateFile(SlotName,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        (LPSECURITY_ATTRIBUTES)NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        (HANDLE)NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("error: shutdown init failed with %d, is 'wdna' running?\n", GetLastError());
        return 1;
    }

    WriteSlot(hFile, TEXT("shutdown"));
    CloseHandle(hFile);

    int counter = 0;
	while(IsProcessRunning("wdna.exe")) {
		printf("info: process 'wdna.exe' is still running, waiting...\n");
        ++counter;
		Sleep(100);
        if (counter == 50) {
            printf("error: unable to shut down the 'wdna.exe' process.\n");
            return 1;
        }
	}

    return 0;
}
