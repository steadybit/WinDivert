#pragma once
#include <windows.h>
#include <stdio.h>


BOOL WINAPI MakeSlot(HANDLE* mail_slot, LPCTSTR slot_name);

#define MAILSLOT_ERROR						0x00000001   
#define MAILSLOT_EMPTY						0x00000002   
#define MAILSLOT_RECEIVE					0x00000003   

DWORD ReadSlot(HANDLE* mail_slot);
