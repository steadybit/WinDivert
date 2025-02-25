#pragma once
#include <windows.h>
#include <wdna_utils.h>

typedef struct Node {
	LPVOID data; 
	struct Node* next;
} NODE;

typedef struct Queue {
	NODE* front;
	NODE* rear;
	HANDLE* mtx;
} QUEUE;

void initQueue(QUEUE* q, HANDLE* mtx);

void enqueue(QUEUE* q, LPVOID data);

void enqueueByTime(QUEUE* q, PACKET_INFO* data);

LPVOID dequeue(QUEUE* q);

LPVOID peak(QUEUE* q);
