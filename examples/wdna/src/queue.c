#include <queue.h>

void initQueue(QUEUE* q, HANDLE* mtx) {
	q->front = q->rear = NULL;
	q->mtx = mtx;
}

void enqueue(QUEUE* q, LPVOID data) {
	NODE* newNode = (NODE*)malloc(sizeof(NODE));
	if (newNode == NULL) {
		printf("Memory allocation failed\n");
		return;
	}

	newNode->data = data;
	newNode->next = NULL;

	WaitForSingleObject(q->mtx, INFINITE);

	if (q->rear == NULL) {
		q->front = q->rear = newNode;
	}
	else {
		q->rear->next = newNode;
		q->rear = newNode;
	}

	ReleaseMutex(q->mtx);
}

LPVOID dequeue(QUEUE* q) {
	WaitForSingleObject(q->mtx, INFINITE);
	if (q->front == NULL) {
		ReleaseMutex(q->mtx);
		return NULL;
	}

	NODE* temp = q->front;
	LPVOID data = temp->data;

	q->front = q->front->next;

	if (q->front == NULL) {
		q->rear = NULL;
	}

	ReleaseMutex(q->mtx);
	free(temp);
	return data;
}


LPVOID peak(QUEUE* q) {
	WaitForSingleObject(q->mtx, INFINITE);
	if (q->front == NULL) {
		ReleaseMutex(q->mtx);
		return NULL;
	}

	NODE* temp = q->front;
	LPVOID data = temp->data;

	ReleaseMutex(q->mtx);
	return data;
}
