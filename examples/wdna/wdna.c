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
#include <cargs.h>
#include <stdbool.h>

#include "windivert.h"
#include <queue.h>

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)
#define htons(x)            WinDivertHelperHtons(x)
#define htonl(x)            WinDivertHelperHtonl(x)

#define MAXBUF              WINDIVERT_MTU_MAX
#define INET6_ADDRSTRLEN    45
#define IPPROTO_ICMPV6      58

/*
 * Pre-fabricated packets.
 */
typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_TCPHDR tcp;
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_ICMPHDR icmp;
    UINT8 data[];
} ICMPPACKET, *PICMPPACKET;

typedef struct
{
    WINDIVERT_IPV6HDR ipv6;
    WINDIVERT_ICMPV6HDR icmpv6;
    UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;

/*
 * Prototypes.
 */
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);
static void PacketIpIcmpInit(PICMPPACKET packet);
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet);
static void PacketIpv6TcpInit(PTCPV6PACKET packet);
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet);

static struct cag_option options[] = {
    {.identifier = 'f',
    .access_letters = "f",
    .access_name = "filter",
    .value_name = "FILTER",
    .description = "WinDivert filter."},
    {.identifier = 'm',
    .access_letters = "m",
    .access_name = "mode",
    .value_name = "MODE",
    .description = "One of the three modes: drop|delay|corrupt."},
    {.identifier = 'j',
    .access_letters = "j",
    .access_name = "jitter",
    .value_name = "JITTER",
    .description = "[MODE:delay] - random +-30% jitter to network delay."},
    {.identifier = 't',
    .access_letters = "t",
    .access_name = "time",
    .value_name = "TIME",
    .description = "[MODE:delay] - how much should traffic be delayed in 'ms'."},
	 {.identifier = 'h',
	.access_letters = "h",
	.access_name = "help",
	.description = "Shows all options."}
};


typedef struct {
    LPVOID main;
};

typedef struct packet_info {
    unsigned char* packet_data;
    UINT packet_len;
    WINDIVERT_ADDRESS* recv_addr;
    LARGE_INTEGER* recv_time;
} PACKET_INFO;

typedef struct wdna_opts {
    QUEUE* queue;
    const char* mode;
    UINT* delay_time;
    HANDLE* wd_handle;
} WDNA_OPTS;

static int ConsumePackets(WDNA_OPTS* opts);
static void PrintPacketQueue(QUEUE* queue);
static DWORD WINAPI ProcessPackets(LPVOID lpParam);
/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    const char* filter = NULL;
    const char* mode = NULL;
    UINT delay_time;
    bool time_taken = false;
    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
        case 'f':
            filter = cag_option_get_value(&context);
            break;

        case 'm': {
            mode = cag_option_get_value(&context);
            if (strcmp("drop", mode) != 0 && strcmp("delay", mode) != 0 && strcmp("corrupt", mode) != 0) {
                printf("Invalid mode '%s'. Allowed modes are: 'drop', 'delay', 'corrupt'.\n", mode);
                return 1;
            }
            break;
        }
        case 't': {
			const char* delay_time_str = NULL;
            delay_time_str = cag_option_get_value(&context);
            delay_time = strtoul(delay_time_str, NULL, 10);
            if (errno != 0) {
                printf("Invalid delay time: %s\n", delay_time_str);
                return 1;
            }
            time_taken = true;
            break;
        }

        case 'h':
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return 0;
        }
    }

    if (filter == NULL) {
        printf("Filter must not be empty.");
        return 1;
    }

    if (mode == NULL) {
        printf("Mode must not be empty.");
        return 1;
    }

    if (time_taken == false && strcmp("delay", mode) == 0) {
        printf("Delay time must not be empty in delay mode.");
        return 1;
    }

    printf("Filter: %s\n", filter);
    
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

    WDNA_OPTS opts = { &packet_queue, mode, &delay_time, &handle };
    DWORD processing_thread_id;
    HANDLE processing_thread = CreateThread(NULL, 0, ProcessPackets, &opts, 0, &processing_thread_id);

    ConsumePackets(&opts);
    WaitForSingleObject(processing_thread, INFINITE);
    CloseHandle(processing_thread);
    printf("Stopping the execution.");
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
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            return 1;
        }

		LARGE_INTEGER* start_time = (LARGE_INTEGER*)malloc(sizeof(LARGE_INTEGER));

        if (start_time == NULL) {
            printf("error: failed to allocate memory for packet receive time.\n");
            return 1;
        }

		QueryPerformanceCounter(start_time);

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
        packet_info->recv_time = start_time;
        enqueue(opts->queue, packet_info);

#ifdef _DEBUG
        //PrintPacketQueue(opts->queue);
#endif
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

/*
 * Initialize a PACKET.
 */
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPHDR));
    packet->Version = 4;
    packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
    packet->Id = ntohs(0xDEAD);
    packet->TTL = 64;
}

/*
 * Initialize a TCPPACKET.
 */
static void PacketIpTcpInit(PTCPPACKET packet)
{
    memset(packet, 0, sizeof(TCPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Length = htons(sizeof(TCPPACKET));
    packet->ip.Protocol = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Initialize an ICMPPACKET.
 */
static void PacketIpIcmpInit(PICMPPACKET packet)
{
    memset(packet, 0, sizeof(ICMPPACKET));
    PacketIpInit(&packet->ip);
    packet->ip.Protocol = IPPROTO_ICMP;
}

/*
 * Initialize a PACKETV6.
 */
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
    memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
    packet->Version = 6;
    packet->HopLimit = 64;
}

/*
 * Initialize a TCPV6PACKET.
 */
static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
    memset(packet, 0, sizeof(TCPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
    packet->ipv6.NextHdr = IPPROTO_TCP;
    packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
 * Initialize an ICMP PACKET.
 */
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
    memset(packet, 0, sizeof(ICMPV6PACKET));
    PacketIpv6Init(&packet->ipv6);
    packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}

typedef struct fiber_info {
    bool done;
    LPVOID fiber_address;
    LPVOID main_fiber_address;
    PACKET_INFO* packet_info;
    HANDLE* wd_handle;
    LARGE_INTEGER* start_time;
    UINT* delay_time;
} FIBER_INFO;

void FiberDelay(LPVOID lpParam) {
    FIBER_INFO* fiber_info = (FIBER_INFO*)lpParam;
    printf("Start time: %lld\n", fiber_info->start_time->QuadPart);
    WINDIVERT_ADDRESS recv_addr;
    UINT packet_len;
    LARGE_INTEGER end_time, frequency, target_ticks, send_time;
    QueryPerformanceFrequency(&frequency);
    UINT sleep_duration = *fiber_info->delay_time;
    target_ticks.QuadPart = fiber_info->start_time->QuadPart + (sleep_duration * frequency.QuadPart) / 1000;

	while (true){
        QueryPerformanceCounter(&end_time);
        if (end_time.QuadPart >= target_ticks.QuadPart) {
            break;
        }
        SwitchToFiber(fiber_info->main_fiber_address);
    } 

    PACKET_INFO* packet_info = fiber_info->packet_info;
    WinDivertSend(*fiber_info->wd_handle, packet_info->packet_data, packet_info->packet_len, &packet_len, packet_info->recv_addr);
    QueryPerformanceCounter(&send_time);
    printf("Sent start time: %lld, end time: %lld, sent time: %lld\n", fiber_info->start_time->QuadPart, end_time.QuadPart, send_time.QuadPart);
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

    if (mtx == NULL) {
        printf("error: create mutex failed %d.\n", GetLastError());
        return 1;
    }

    initQueue(&fiber_queue, &mtx);
    printf("Process mode: '%s'", opts->mode);

    if (strcmp(opts->mode, "delay") == 0) {
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
                fiber_info->delay_time = opts->delay_time;
                fiber_info->packet_info = packet;
                fiber_info->main_fiber_address = main_fiber;
                fiber_info->done = false;
                fiber_info->start_time = packet->recv_time;
                LPVOID delayFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)FiberDelay, fiber_info);
                fiber_info->fiber_address = delayFiber;
                enqueue(&fiber_queue, fiber_info);
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
                free(fiber_info->start_time);
                free(fiber_info->packet_info);
                free(fiber_info);
            }
        }
    }
    return 0;
}
