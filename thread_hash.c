//luke klotz
//lklotz@pdx.edu
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include "thread_hash.h"
#include <stdbool.h>
#include <crypt.h>

#define BUFFER 4000
#define MAX_PASSWDS 40000

static char * input_file = NULL;
static char * output_file = NULL;
static char * dict_file = NULL;
static char ** passwd_arr = NULL;
static char ** hash_arr = NULL;

static int pass_count;
static int hash_count;

static bool input = false;   //-i
static bool output = false;  //-o
static bool dict = false;    //-d
static bool threads = false; //-t
static bool verbose = false; //-v
static bool help = false;    //-h
static bool nice_mode = false;    //-n


//definitions
char ** getPasswds(FILE *fd);
char ** getHashes(FILE *fp);
void crack(char * passwd, char * hash_string);
void free_passwd_arr(void);
void free_hash_arr(void);

//structs
/*
static struct hash {
	hash_algorithm_t algo;
	char * salt;
	char * hash_string;
}
*/

//hash * hashes = NULL;

int main(int argc, char * argv[]){
	
	if(argc < 2){ 
		printf("argc: %d\n", argc);
	}
	
	{
		//DELETE ME
		hash_algorithm_t algo = SHA256;
		printf("Algorithm: %s\n", algorithm_string[algo]);
	}
	
	{
		int opt = 0;
		while((opt = getopt(argc, argv, OPTIONS)) != -1){
			switch(opt){
				case 'i':
					//hash strings
					input = true;
					input_file = optarg;
					break;
				case 'o':
					output = true;
					output_file = optarg;
					break;
				case 'd':
					dict = true;
					dict_file = optarg;
					break;
				case 't':
					threads = true;
					break;
				case 'v':
					verbose = true;
					break;
				case 'h':
					help = true;
					break;
				case 'n':
					nice_mode = true;
					break;
				default:
					printf("invalid option\n");	
					break;
			}
		}
	}	
	//logic tree begin	

	if(dict){
		FILE *fp = STDIN_FILENO;
		if(dict_file != NULL){
			fp = fopen(dict_file, "r");		
		}

		passwd_arr = getPasswds(fp);
	}
	if(input){
		FILE *fp = STDIN_FILENO;
		if(input_file){
			fp = fopen(input_file, "r");					
		}	
		
		hash_arr = getHashes(fp);
	}

	if(passwd_arr != NULL){
		free_passwd_arr();
	}
	if(hash_arr != NULL){
		free_hash_arr();
	}

	exit(EXIT_SUCCESS);
}
//func defs begin

void free_passwd_arr(void){
	for(int i = 0; i < pass_count; i++){
		free(passwd_arr[i]);
	}		
	free(passwd_arr);
}

void free_hash_arr(void){
	for(int i = 0; i < hash_count; i++){
		free(hash_arr[i]);
	}		
	free(hash_arr);
}

char ** getPasswds(FILE *fp){
	char buff[BUFFER];
	int i = 0;
	passwd_arr = malloc(MAX_PASSWDS * sizeof(char *));
	if(!passwd_arr){
		perror("malloc");
		return NULL;	
	}

	while(fgets(buff, sizeof(buff), fp) != NULL && i < MAX_PASSWDS) {
		buff[strcspn(buff, "\n")] = '\0';
		passwd_arr[i] = strdup(buff);
		if(passwd_arr[i] == NULL){
			perror("strdup");
			for(int j = 0; j < i; j++){
				free(passwd_arr[j]);	
			}
			free(passwd_arr);
			return NULL;
		}
		//printf("Password: %s\n ", passwd_arr[i]);
		++i;
	}			
	pass_count = i;
	return passwd_arr;
}

char ** getHashes(FILE *fp){
	char buff[BUFFER];
	int i = 0;
	hash_arr = malloc(MAX_PASSWDS * sizeof(char *));
	if(!hash_arr){
		perror("malloc");
		return NULL;	
	}
	if(verbose) { printf("PRE loop in getHashes(FILE *fp)\n"); }
	while(fgets(buff, sizeof(buff), fp) != NULL && i < MAX_PASSWDS) {
		if(verbose) { printf("IN loop in getHashes(FILE *fp) at i = %d\n", i); }
		buff[strcspn(buff, "\n")] = '\0';
		hash_arr[i] = strdup(buff);
		if(hash_arr[i] == NULL){
			perror("strdup");
			for(int j = 0; j < i; j++){
				free(hash_arr[j]);	
			}
			free(hash_arr);
			return NULL;
		}
		if(verbose){ printf("Hash: %s\n ", hash_arr[i]); }
		++i;
	}			
	hash_count = i;
	return hash_arr;
}

void crack(char * passwd, char * hash_string){
	struct crypt_data data;
	char * res = NULL;
	data.initialized = 0;

	res = crypt_r(passwd, hash_string, &data);
	if(res && strcmp(res, hash_string) == 0){
		printf("SUCCESS: cracked < %s > using hash < %s >\n", passwd, hash_string);
		;
	} else {
		printf("FAIL: password < %s > using hash < %s > \n", passwd, hash_string);	
	}
}
