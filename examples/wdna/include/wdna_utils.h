#pragma once
#include <windows.h>
#include <windivert.h>
#include <stdbool.h>

typedef struct packet_info {
	unsigned char* packet_data;
	UINT packet_len;
	WINDIVERT_ADDRESS* recv_addr;
	LARGE_INTEGER* recv_time;
	LARGE_INTEGER* target_time;
} PACKET_INFO;

extern bool MAIN_THREAD_FINISHED;
