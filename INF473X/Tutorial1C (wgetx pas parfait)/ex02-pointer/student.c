/*
 * student.c
 *
 *  Created on: Feb 15, 2016
 *      Author: jiaziyi
 */

#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include "student.h"

/**
 * print the student's information
 */
void print_student(student a)
{
	printf("Given name: %s", a.given_name);
	printf("\nAge: %d", a.age);
	printf("\nFamily name: %s", a.family_name);
	printf("\nGender: %s", a.gender);
	printf("\nPromotion: %d\n", *(a.promotion));
}

/**
 * try to modify the student information
 */
void modify(student s, char *given_name, int age, char gender[])
{
	s.given_name = given_name;
	strcpy(s.gender, gender);
	s.age = age;
}

/**
 * try to modify the student information using pointer
 */
void modify_by_pointer(student *s, char *given_name, int age, char gender[])
{
	s->given_name = given_name;
	strcpy(s->gender, gender);
	s->age = age;	
}

student* create_student(char *given_name, char *family_name, int age,
		char* gender, int *promotion)
{
	student *s= malloc(100);//we could just have used static student s as well an treat it as a student
	s->given_name = given_name;
	s->family_name = family_name;
	s->age = age;
	strncpy(s->gender, gender, strlen(gender)+1);
	s->promotion = promotion;
	puts("---print inside create_student function---");
	print_student(*s);
	puts("---end of print inside");
	return s;
}
