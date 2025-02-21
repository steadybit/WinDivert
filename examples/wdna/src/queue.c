#include <queue.h>
#include <wdna_utils.h>

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

void enqueueByTime(QUEUE* q, PACKET_INFO* data) {
	NODE* newNode = (NODE*)malloc(sizeof(NODE));
	if (newNode == NULL) {
		printf("Memory allocation failed\n");
		return;
	}

	newNode->data = data;
	newNode->next = NULL;

	WaitForSingleObject(q->mtx, INFINITE);
	if (q->front == NULL) {
		q->front = q->rear = newNode;
	}
	else if (((PACKET_INFO*)q->front->data)->target_time > data->target_time) {
		newNode->next = q->front;
		q->front = newNode;
	}
	else {
		NODE* current = q->front;
		while (current->next != NULL && ((PACKET_INFO*)current->next->data)->target_time <= data->target_time) {
			current = current->next;
		}

		newNode->next = current->next;
		current->next = newNode;

		if (newNode->next == NULL) {
			q->rear = newNode;
		}
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
