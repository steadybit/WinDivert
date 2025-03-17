#include <windows.h>
#include <stdio.h>

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
        return FALSE;
    }

    WriteSlot(hFile, TEXT("shutdown"));
    CloseHandle(hFile);
    return TRUE;
}
