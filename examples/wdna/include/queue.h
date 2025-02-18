#pragma once
#include <windows.h>

typedef struct Node {
	LPVOID data; 
	struct Node* next;
} NODE;

typedef struct Queue {
	NODE* front;
	NODE* rear;
	HANDLE* mtx;
} QUEUE;

// 1 2 3 4 5 6 7

void initQueue(QUEUE* q, HANDLE* mtx);

void enqueue(QUEUE* q, LPVOID data);

LPVOID dequeue(QUEUE* q);
