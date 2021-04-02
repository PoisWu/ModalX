/*
 * mutex.c
 *
 *  Created on: Mar 19, 2016
 *      Author: jiaziyi
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#define NTHREADS 50
void *increase_counter(void *);


int  counter = 0;

int main(){

	for(int i=0;i<50;i++){
		pthread_t t;
		if(pthread_create(&t,NULL,increase_counter,NULL)){
			fprintf(stderr,"Error creating thread/n");
		}
		pthread_join(t,NULL);
	}

	//create 50 threads of increase_counter, each thread adding 1 to the counter


	printf("\nFinal counter value: %d\n", counter);
	return 0;
}

void *increase_counter(void *arg){
	printf("Thread number %ld, working on counter. The current value is %d\n", (long)pthread_self(), counter);
	int j = counter;
	usleep (10000); //simulate the data processing
	counter = j+1;
	pthread_exit(NULL);
}
