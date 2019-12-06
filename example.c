#include <stdio.h>
#include <pthread.h>
#include "atomic_incr.h"

int A[10];
int B[10];
int C[10];
pthread_mutex_t lock;

void *thread_start(void *arg) {
    int i;
    for (i=0; i < 10; i++) {
        atomic_incr(&C[i], 1);
    }
}

int main() {
    pthread_t t;
    int i,j;
    for(i = 0; i < 10; i++) {
        A[i] = i;
        B[i] = i;
        C[i] = 1;
    }

    pthread_create(&t, NULL, thread_start, NULL);
    for(j = 0; j < 10; j++) {
        pthread_mutex_lock(&lock);
        C[j] = C[j] + A[j] * B[j];
        pthread_mutex_unlock(&lock);
    }

    if(C[9] == 81) {
        printf("Yay\n");
    } else {
        printf("oops %d\n", C[9]);
    }
    pthread_join(t, NULL);
    return 69;
}
