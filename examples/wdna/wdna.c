/*
 * netfilter.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 * This is a simple traffic filter/firewall using WinDivert.
 *
 * usage: netfilter.exe windivert-filter [priority]
 *
 * Any traffic that matches the windivert-filter will be blocked using one of
 * the following methods:
 * - TCP: send a TCP RST to the packet's source.
 * - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
 * - ICMP/ICMPv6: Drop the packet.
 *
 * This program is similar to Linux's iptables with the "-j REJECT" target.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cli.h>

#include <windivert.h>
#include <wdna_utils.h>
#include <queue.h>
#include <mailslot.h>

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define htons(x)            WinDivertHelperHtons(x)
#define htonl(x)            WinDivertHelperHtonl(x)

#define MAXBUF              WINDIVERT_MTU_MAX
#define INET6_ADDRSTRLEN    45
#define IPPROTO_ICMPV6      58

typedef struct wdna_opts {
	HANDLE* wd_handle;
	QUEUE* queue;
	CLI_OPTS* cli_opts;
	LARGE_INTEGER* end_time;
} WDNA_OPTS;

typedef struct fiber_info {
	bool done;
	LPVOID fiber_address;
	LPVOID main_fiber_address;
	PACKET_INFO* packet_info;
	HANDLE* wd_handle;
	CLI_OPTS* cli_opts;
} FIBER_INFO;

static const char* ReadFileContent(const char* filename);
static int ConsumePackets(WDNA_OPTS* opts);
static void PrintPacketQueue(QUEUE* queue);
static DWORD WINAPI ProcessPackets(LPVOID lpParam);
static DWORD WINAPI Terminate(LPVOID lpParam);
static DWORD WINAPI Mailslot(LPVOID lpParam);
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);

int __cdecl main(int argc, char **argv)
{
	srand(time(NULL));
	SetConsoleCtrlHandler(CtrlHandler, TRUE);
	CLI_OPTS cli_opts;
	InitCLIOpts(&cli_opts);
	int cli_opts_status = ParseCLIOpts(&cli_opts, argc, argv);

	if (cli_opts_status != 0) {
		return cli_opts_status;
	}

	PrintCLIOpts(&cli_opts);

    const char* filter = ReadFileContent(cli_opts.file);
    if (filter == NULL) {
        printf("error: reading content of filter file %s.\n", cli_opts.file);
        return 1;
    }
    printf("Filter: '%s'\n", filter);

	LARGE_INTEGER end_time, start_time, frequency;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start_time);

	end_time.QuadPart = start_time.QuadPart + ((cli_opts.duration * 1000) * frequency.QuadPart) / 1000;

	QUEUE packet_queue;
	HANDLE mtx = CreateMutex(NULL, FALSE, NULL);

	if (mtx == NULL) {
		printf("error: create mutex failed %d.\n", GetLastError());
		return 1;
	}

	initQueue(&packet_queue, &mtx);

	HANDLE handle;
	int priority = 0;
	handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, (INT16)priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	WDNA_OPTS opts = { &handle, &packet_queue, &cli_opts, &end_time };

	DWORD mailslot_thread_id;
	HANDLE mailslot_thread = CreateThread(NULL, 0, Mailslot, &opts, 0, &mailslot_thread_id);

	if (mailslot_thread == NULL) {
		printf("error: failed to create a packet processing thread.");
		return 1;
	}

	DWORD processing_thread_id;
	HANDLE processing_thread = CreateThread(NULL, 0, ProcessPackets, &opts, 0, &processing_thread_id);

	if (processing_thread == NULL) {
		printf("error: failed to create a packet processing thread.");
		return 1;
	}

	DWORD terminate_thread_id;
	HANDLE terminate_thread = CreateThread(NULL, 0, Terminate, &opts, 0, &terminate_thread_id);

	if (terminate_thread == NULL) {
		printf("error: failed to create a termination thread.");
		return 1;
	}


	ConsumePackets(&opts);
	WaitForSingleObject(processing_thread, INFINITE);
	CloseHandle(processing_thread);
	return 0;
}

static int ConsumePackets(WDNA_OPTS* opts) {
	unsigned char* packet = (unsigned char*)malloc(MAXBUF * sizeof(unsigned char));

	if (packet == NULL) {
		printf("Packet memory allocation failed!\n");
		return 1;
	}

	UINT packet_len, recv_len, addr_len;
	WINDIVERT_ADDRESS recv_addr;
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);

	while (TRUE)
	{
		if (!WinDivertRecv(*opts->wd_handle, packet, MAXBUF, &packet_len,
			&recv_addr)) {
			DWORD last_error = GetLastError();

			if (last_error == ERROR_NO_DATA) {
				MAIN_TERMINATED = true;
				return 0;
			}

			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			return 1;
		}


		unsigned char* packet_copy = (unsigned char*)malloc(packet_len);
		if (packet_copy == NULL) {
			printf("error: failed to allocate memory for packet copy.\n");
			return 1;
		}

		memcpy(packet_copy, packet, packet_len);

		WINDIVERT_ADDRESS* recv_addr_copy = (WINDIVERT_ADDRESS*)malloc(sizeof(WINDIVERT_ADDRESS));

		if (recv_addr_copy == NULL) {
			printf("error: failed to allocate ememory for packet copy.\n");
			return 1;
		}

		memcpy(recv_addr_copy, &recv_addr, sizeof(WINDIVERT_ADDRESS));

		PACKET_INFO* packet_info = (PACKET_INFO*)malloc(sizeof(PACKET_INFO));

		if (packet_info == NULL) {
			printf("error: failed to allocate memory for PACKET_INFO.\n");
			return 1;
		}


		packet_info->packet_data = packet_copy;
		packet_info->packet_len = packet_len;
		packet_info->recv_addr = recv_addr_copy;

		if (strcmp(opts->cli_opts->mode, "delay") == 0) {
			LARGE_INTEGER* start_time = (LARGE_INTEGER*)malloc(sizeof(LARGE_INTEGER));

			if (start_time == NULL) {
				printf("error: failed to allocate memory for packet receive time.\n");
				return 1;
			}

			QueryPerformanceCounter(start_time);

			LARGE_INTEGER* target_time = (LARGE_INTEGER*)malloc(sizeof(LARGE_INTEGER));

			if (target_time == NULL) {
				printf("error: failed to allocate memory for packet target time.\n");
				return 1;
			}

			unsigned int wait_time = opts->cli_opts->time;

			if (opts->cli_opts->jitter) {
				unsigned int jitter = rand() % (int)(0.3 * opts->cli_opts->time + 1);
				unsigned int operation = rand() % 2;

				if (operation == 0) {
					wait_time += jitter;
				}
				else if(operation == 1) {
					wait_time -= jitter;
				}
			}

			target_time->QuadPart = start_time->QuadPart + ((wait_time) * frequency.QuadPart) / 1000;

			packet_info->recv_time = start_time;
			packet_info->target_time = target_time;

			if (opts->cli_opts->jitter) {
				enqueueByTime(opts->queue, packet_info);
			}
			else {
				enqueue(opts->queue, packet_info);
			}
		}
		else {
			enqueue(opts->queue, packet_info);
		}
	}
	return 0;
}

static void PrintPacketQueue(QUEUE* queue) {
	if (queue == NULL) {
		printf("error: queue is not initialized (null).");
		return;
	}
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	UINT32 src_addr[4], dst_addr[4];
	char src_str[INET6_ADDRSTRLEN+1], dst_str[INET6_ADDRSTRLEN+1];

	printf("printing queue data:\n");
	NODE* temp = queue->front;

	while (temp != NULL) {
		PACKET_INFO* data = (PACKET_INFO*)(temp->data);
		WinDivertHelperParsePacket(data->packet_data, data->packet_len, &ip_header, &ipv6_header,
			NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
			&payload_len, NULL, NULL);

		if (ip_header != NULL)
		{
			WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr),
				src_str, sizeof(src_str));
			WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr),
				dst_str, sizeof(dst_str));
		}
		if (ipv6_header != NULL)
		{
			WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
			WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
			WinDivertHelperFormatIPv6Address(src_addr, src_str,
				sizeof(src_str));
			WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
				sizeof(dst_str));
		}

		printf("ip.SrcAddr=%s ip.DstAddr=%s \n", src_str, dst_str);
		temp = temp->next;
	}
}

void FiberDelay(LPVOID lpParam) {
	FIBER_INFO* fiber_info = (FIBER_INFO*)lpParam;
	//printf("Start time: %lld\n", fiber_info->packet_info->target_time->QuadPart);
	WINDIVERT_ADDRESS recv_addr;
	UINT packet_len;
	LARGE_INTEGER end_time, frequency, send_time;
	QueryPerformanceFrequency(&frequency);
	UINT sleep_duration = fiber_info->cli_opts->time;

	while (true){
		QueryPerformanceCounter(&end_time);
		if (end_time.QuadPart >= fiber_info->packet_info->target_time->QuadPart) {
			break;
		}
		SwitchToFiber(fiber_info->main_fiber_address);
	} 

	PACKET_INFO* packet_info = fiber_info->packet_info;
	WinDivertSend(*fiber_info->wd_handle, packet_info->packet_data, packet_info->packet_len, &packet_len, packet_info->recv_addr);
	QueryPerformanceCounter(&send_time);
	//printf("Sent start time: %lld, end time: %lld, sent time: %lld\n", fiber_info->packet_info->target_time->QuadPart, end_time.QuadPart, send_time.QuadPart);
	fiber_info->done = true;
	SwitchToFiber(fiber_info->main_fiber_address);
}

static DWORD WINAPI ProcessPackets(LPVOID lpParam) {
	typedef struct delay_fiber_opts {
		LPVOID main_fiber;
		PACKET_INFO* packet_info;
		WDNA_OPTS* wdna_opts;
	} DELAY_FIBER_OPTS;


	WDNA_OPTS* opts = (WDNA_OPTS*)lpParam;
	QUEUE* packet_queue = opts->queue;
	QUEUE fiber_queue;
	HANDLE mtx = CreateMutex(NULL, FALSE, NULL);
	bool shutdown_initiated = false;

	if (mtx == NULL) {
		printf("error: create mutex failed %d.\n", GetLastError());
		return 1;
	}

	initQueue(&fiber_queue, &mtx);

	if (strcmp(opts->cli_opts->mode, "corrupt") == 0) {
		PACKET_INFO* packet_info;
		UINT packet_len;
		while (true) {
			if (packet_info = (PACKET_INFO*)dequeue(packet_queue)) {
				unsigned int chance = rand() % 100;

				if (chance < opts->cli_opts->percentage) {
					size_t byte_index = rand() % packet_info->packet_len;
					size_t bit_index = rand() % 8;
					packet_info->packet_data[byte_index] ^= (1 << bit_index);

					WinDivertHelperCalcChecksums(packet_info->packet_data, packet_info->packet_len, packet_info->recv_addr, 0);
				}

				WinDivertSend(*opts->wd_handle, packet_info->packet_data, packet_info->packet_len, &packet_len, packet_info->recv_addr);

				free(packet_info->packet_data);
				free(packet_info->recv_addr);
			}
			else {
				// Terminate only after all of the packets in the queue have been sent.
				if (TERMINATE_THREADS && !shutdown_initiated) {
#ifdef _DEBUG
					printf("warn: shutdown initiated. \n");
#endif
					shutdown_initiated = true;
					WinDivertShutdown(*opts->wd_handle, WINDIVERT_SHUTDOWN_RECV);
				}

				if (TERMINATE_THREADS && MAIN_TERMINATED && peak(packet_queue) == NULL) {
#ifdef _DEBUG
					printf("warn: terminated processing. \n");
#endif
					break;
				}
			}
		}

		return 0;
	} 

	if (strcmp(opts->cli_opts->mode, "drop") == 0) {
		PACKET_INFO* packet_info;
		UINT packet_len;
		while (true) {
			if (packet_info = (PACKET_INFO*)dequeue(packet_queue)) {
				UINT8 chance = rand() % 100;

	            if (chance >= opts->cli_opts->percentage) { // less than this is drop.
					WinDivertSend(*opts->wd_handle, packet_info->packet_data, packet_info->packet_len, &packet_len, packet_info->recv_addr);
	            }

				free(packet_info->packet_data);
				free(packet_info->recv_addr);
			}
			else {
				// Terminate only after all of the packets in the queue have been sent.
				if (TERMINATE_THREADS && !shutdown_initiated) {
#ifdef _DEBUG
					printf("warn: shutdown initiated. \n");
#endif
					shutdown_initiated = true;
					WinDivertShutdown(*opts->wd_handle, WINDIVERT_SHUTDOWN_RECV);
				}

				if (TERMINATE_THREADS && MAIN_TERMINATED && peak(packet_queue) == NULL) {
#ifdef _DEBUG
					printf("warn: terminated processing. \n");
#endif
					break;
				}
			}
		}
		return 0;
	}

	if (strcmp(opts->cli_opts->mode, "delay") == 0) {
		LPVOID main_fiber = ConvertThreadToFiber(NULL);
		PACKET_INFO* packet;
		LARGE_INTEGER frequency;
		QueryPerformanceFrequency(&frequency);
		while (true) {
			if (packet = (PACKET_INFO*)dequeue(packet_queue)) {
				FIBER_INFO* fiber_info = (FIBER_INFO*)malloc(sizeof(FIBER_INFO));

				if (fiber_info == NULL) {
					printf("error: failed allocating memory for 'FIBER_INFO'.");
					return 1;
				}

				fiber_info->wd_handle = opts->wd_handle;
				fiber_info->packet_info = packet;
				fiber_info->main_fiber_address = main_fiber;
				fiber_info->done = false;
				fiber_info->cli_opts = opts->cli_opts;
				LPVOID delayFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)FiberDelay, fiber_info);
				fiber_info->fiber_address = delayFiber;
				enqueue(&fiber_queue, fiber_info);
			} else {
				// Terminate only after all of the packets in the queue have been sent.
				if (TERMINATE_THREADS && !shutdown_initiated) {
#ifdef _DEBUG
					printf("warn: shutdown initiated. \n");
#endif
					shutdown_initiated = true;
					WinDivertShutdown(*opts->wd_handle, WINDIVERT_SHUTDOWN_RECV);
				}

				if (TERMINATE_THREADS && MAIN_TERMINATED && peak(packet_queue) == NULL && peak(&fiber_queue) == NULL) {
#ifdef _DEBUG
					printf("warn: terminated processing. \n");
#endif
					break;
				}
			}

			FIBER_INFO* fiber_info = (FIBER_INFO*)peak(&fiber_queue);
			if (fiber_info == NULL) {
				Sleep(0);
				continue;
			}
			SwitchToFiber(fiber_info->fiber_address);
			if (fiber_info->done) {
				dequeue(&fiber_queue);
				DeleteFiber(fiber_info->fiber_address);
				free(fiber_info->packet_info->packet_data);
				free(fiber_info->packet_info->recv_addr);
				free(fiber_info->packet_info->target_time);
				free(fiber_info->packet_info->recv_time);
				free(fiber_info->packet_info);
				free(fiber_info);
			}

		}
	}
	return 0;
}

static const char* ReadFileContent(const char* filename)
{
	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		fprintf(stderr, "error: failed to open file %s\n", filename);
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Allocate memory for the entire file content plus null terminator
	char* buffer = (char*)malloc(file_size + 1);
	if (buffer == NULL) {
		fprintf(stderr, "error: failed to allocate memory for file content\n");
		fclose(file);
		return NULL;
	}

	size_t read_size = fread(buffer, 1, file_size, file);
	fclose(file);

	if (read_size != file_size) {
		fprintf(stderr, "error: failed to read complete file content\n");
		free(buffer);
		return NULL;
	}
	buffer[file_size] = '\0';
	return buffer;
}
static DWORD WINAPI Terminate(LPVOID lpParam) {
	WDNA_OPTS* opts = (WDNA_OPTS*)lpParam;

	Sleep(opts->cli_opts->duration * 1000);
	TERMINATE_THREADS = true;

	return 0;
}

static DWORD WINAPI Mailslot(LPVOID lpParam) {
	HANDLE mail_slot;
	LPCTSTR slot_name = TEXT("\\\\.\\mailslot\\steadybit\\wdna");

	if (!MakeSlot(&mail_slot, slot_name)) {
		return 1;
	}

	while (true) {
		DWORD result = ReadSlot(&mail_slot);

		if (result == MAILSLOT_ERROR) {
			TERMINATE_THREADS = true;
			return 1;
		}

		if (result == MAILSLOT_EMPTY) {
			Sleep(1000);
			continue;
		}

		if (result == MAILSLOT_RECEIVE) {
			break;
		}
	}

	TERMINATE_THREADS = true;
	CloseHandle(mail_slot);
	return 0;
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
	switch (fdwCtrlType) {
		case CTRL_C_EVENT:
#ifdef _DEBUG
			printf("Handled CTRL C\n");
#endif
			TERMINATE_THREADS = true;
			return TRUE;

		case CTRL_CLOSE_EVENT:
#ifdef _DEBUG
			printf("Handled CTRL CLOSE\n");
#endif
			TERMINATE_THREADS = true;
			return TRUE;

		case CTRL_BREAK_EVENT:
#ifdef _DEBUG
			printf("Handled CTRL BREAK\n");
#endif
			TERMINATE_THREADS = true;
			return TRUE;

		case CTRL_LOGOFF_EVENT:
#ifdef _DEBUG
			printf("Handled LOGOFF\n");
#endif
			return FALSE;

		case CTRL_SHUTDOWN_EVENT:
#ifdef _DEBUG
			printf("Handled SHUTDOWN\n");
#endif
			return FALSE;

		default:
#ifdef _DEBUG
			printf("Handled DEFAULT\n");
#endif
			return FALSE;
	}
}
