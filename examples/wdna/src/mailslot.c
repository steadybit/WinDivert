#include <mailslot.h>

BOOL WINAPI MakeSlot(HANDLE* mail_slot, LPCTSTR slot_name) {
	*mail_slot = CreateMailslot(slot_name, 0, MAILSLOT_WAIT_FOREVER, (LPSECURITY_ATTRIBUTES) NULL);
	if (mail_slot == INVALID_HANDLE_VALUE) {
		printf("error: mailslot creation failed with %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

DWORD ReadSlot(HANDLE* mail_slot) {
	DWORD cbMessage, cMessage;
	BOOL fResult;

	cbMessage = cMessage = 0;

	fResult = GetMailslotInfo(*mail_slot, (LPDWORD) NULL, &cbMessage, &cMessage, (LPDWORD) NULL);

	if (!fResult) {
		printf("error: mailslot info failed with %d. \n", GetLastError());
		return MAILSLOT_ERROR;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE) {
		return MAILSLOT_EMPTY;
	}

	if (cMessage != 0) {
		return MAILSLOT_RECEIVE;
	}

	printf("error: mailslot error. \n");
	return MAILSLOT_ERROR;
}
