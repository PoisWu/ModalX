#include<stdio.h>
#include <pthread.h>

pthread_t thread_a, thread_b;
pthread_cond_t last =PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;

char c='b';
void *do_a(){
    while(1){
        pthread_mutex_lock(&lock);            // START critical region
        while(c!='b'){
            pthread_cond_wait(&last,&lock);
        }
        printf("a\n");
        c='a';
        pthread_cond_signal(&last);
        pthread_mutex_unlock(&lock);          // END critical region
    }
    return NULL;
}
void *do_b(){
    while(1){
        pthread_mutex_lock(&lock);            // START critical region
        while(c!='a'){
            pthread_cond_wait(&last,&lock);
        }
        printf("b\n");
        c='b';
        pthread_cond_signal(&last);
        pthread_mutex_unlock(&lock);          // END critical region
    }
    return NULL;
}

int main(){
    if(pthread_create(&thread_a, NULL, do_a, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }
    if (pthread_mutex_init(&lock, NULL) != 0){
        printf("\n mutex init failed\n");
        return 1;
    }
    do_b();
    return 0;
}