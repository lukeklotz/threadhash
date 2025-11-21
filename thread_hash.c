//luke klotz
//lklotz@pdx.edu
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <crypt.h>
//#include "thread_hash.h"

#define BUFFER 4000
#define MAX_LIST_SIZE 40000
#define MAX_THREAD 24
#define MIN_THREAD 1
# define OPTIONS "i:o:d:hvt:n"

static char * input_file = NULL;
static char * output_file = NULL;
static char * dict_file = NULL;
static char ** passwd_arr = NULL;
static char ** hash_arr = NULL;

static int pass_count;
static int hash_count;
static int num_threads = 1;
static int out_fd = STDOUT_FILENO;

static bool input = false;   //-i
static bool output = false;  //-o
static bool dict = false;    //-d
static bool verbose = false; //-v
static bool help = false;    //-h
static bool nice_mode = false;    //-n

typedef struct {
	int des;
	int nt;
	int md5;
	int s256;
	int s512;
	int y;
	int gh;
	int bcry;	

	int total;
	int failed;
} al_count_t;

static al_count_t total_alg_count;

//definitions
char ** getPasswds(FILE *fd);
char ** getHashes(FILE *fp);
bool crack(char*, char*);
void free_passwd_arr(void);
void free_hash_arr(void);
int get_next_index(void);
void * loop_hashes(void*);
char * get_algo(char * hash);
void algo_counter(char * hash, al_count_t * alg_c);
void getHashType(char *hash, al_count_t * alg_c);

/*
//structs
typedef struct{
	char * passwd;
	char * hash_string;
} hash_pass_struct_t;

static hash_pass_struct_t st;
*/
int main(int argc, char * argv[]){

		
	if(argc < 2){ 
		printf("argc: %d\n", argc);
	}	

	{
	///	hash_algorithm_t algo = SHA256;
	//	printf("Algorithm: %s\n", algorithm_string[algo]);
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
					num_threads = atoi(optarg);
					if (num_threads > MAX_THREAD){
						num_threads = MAX_THREAD;		
					} else if (num_threads < MIN_THREAD){
						num_threads = 1;	
					}
					break;
				case 'v':
					verbose = true;
					break;
				case 'h':
					help = true;
					break;
				case 'n':
					nice(10);
					nice_mode = true;
					break;
				default:
					printf("invalid option\n");	
					break;
			}
		}
	}	

	if(help){
		fprintf(stderr, "help text\n");
		fprintf(stderr, "\t./thread_hash ...\n");
		fprintf(stderr, "\tOptions: i:o:d:hvt:n\n");
		fprintf(stderr, "\t\t-i file\t\thash file name (required)\n");
		fprintf(stderr, "\t\t-o file\t\toutput file name (default stdout)\n");
		fprintf(stderr, "\t\t-d file\t\tdictionary file name (required)\n");
		fprintf(stderr, "\t\t-t #\t\tnumber of threads to create (default == 1)\n");
		fprintf(stderr, "\t\t-n\t\trenice to 10\n");
		fprintf(stderr, "\t\t-v\t\tenable verbose mode\n");
		fprintf(stderr, "\t\t-h\t\thelpful text\n");	
		exit(EXIT_SUCCESS);	
	}
	
	//logic tree begin	
	if(dict){
		FILE *fp = STDIN_FILENO;
		if(dict_file != NULL){
			fp = fopen(dict_file, "r");		
		}

		passwd_arr = getPasswds(fp);
	} else {
		fprintf(stderr, "must give name for dictionary input file with -d filename\n");	
		exit(EXIT_FAILURE);
	}
	if(input){
		FILE *fp = STDIN_FILENO;
		if(input_file){
			fp = fopen(input_file, "r");					
		}	
		
		hash_arr = getHashes(fp);
	} else {
		fprintf(stderr, "must give name for hashed password input file with -t filename\n");	
		exit(EXIT_FAILURE);	
	}
	if(output){
		out_fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);		
		if(out_fd < 0){
			fprintf(stderr, "Error: opening output file\n");	
			exit(EXIT_FAILURE);
		}
	}
	if(dict && input) {
		//loop hashes	
		pthread_t *threads = NULL;			
		long tid = 0;
		double elapsed = 0;
		struct timespec st, end;
		clock_gettime(CLOCK_MONOTONIC, &st);
	
		memset(&total_alg_count, 0, sizeof(total_alg_count));

		threads = malloc(num_threads * sizeof(pthread_t));
		
		if(verbose) { printf("before pthread_create\n"); }

		for(tid = 0; tid < num_threads; tid++){	
			pthread_create(&threads[tid], NULL, loop_hashes, (void*)(intptr_t)tid);	
		}
		for(tid = 0; tid < num_threads; tid++){
			pthread_join(threads[tid], NULL);
		}
		
		clock_gettime(CLOCK_MONOTONIC, &end);
	
		elapsed = (end.tv_sec - st.tv_sec) + 
	                 (end.tv_nsec - st.tv_nsec) / 1000000000.0;

		fprintf(stderr, "total: %3d", num_threads); 
		fprintf(stderr, " %8.2f sec", elapsed); 
		fprintf(stderr, "              DES: %5d", total_alg_count.des); 
		fprintf(stderr, "               NT: %5d", total_alg_count.nt); 
		fprintf(stderr, "              MD5: %5d", total_alg_count.md5); 
		fprintf(stderr, "           SHA256: %5d", total_alg_count.s256); 
		fprintf(stderr, "           SHA512: %5d", total_alg_count.s512); 
		fprintf(stderr, "         YESCRYPT: %5d", total_alg_count.y); 
		fprintf(stderr, "    GOST_YESCRYPT: %5d", total_alg_count.gh); 
		fprintf(stderr, "           BCRYPT: %5d", total_alg_count.bcry); 
		fprintf(stderr, "  total: %8d", total_alg_count.total); 
		fprintf(stderr, "  failed: %8d\n", total_alg_count.failed); 
		free(threads);	
	}
	
	//free memory
	if(passwd_arr != NULL){
		free_passwd_arr();
	}
	if(hash_arr != NULL){
		free_hash_arr();
	}

	exit(EXIT_SUCCESS);
}
//func defs begin
int get_next_index(void){
	static int next_hash = 0;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;	
	int cur_hash = 0;
	
	pthread_mutex_lock(& lock);
	cur_hash = next_hash++;
	pthread_mutex_unlock(& lock);

	return cur_hash;
}

void * loop_hashes(void * arg){
	int tid = (int)(intptr_t)arg;
	int count = 0;
	int fail_count = 0;
	int i = 0;
	double elapsed = -1;
	al_count_t alg_c = {0};

	struct timespec st, end;
	clock_gettime(CLOCK_MONOTONIC, &st);
	
	for(i = get_next_index(); i < hash_count; i = get_next_index()){
		//algo_counter(get_algo(hash_arr[i]), &alg_c);	
		getHashType(hash_arr[i], &alg_c);
		for(int j = 0; j < pass_count; ++j){
			if(crack(passwd_arr[j], hash_arr[i]) == true){
				dprintf(out_fd, "cracked  %s  %s\n", passwd_arr[j], hash_arr[i]);
				++count;
				break;
			}
			else if ((j == pass_count - 1) && (crack(passwd_arr[j], hash_arr[i]) == false)){
				dprintf(out_fd, "*** failed to crack  %s\n", hash_arr[i]);
				++fail_count;
				++count;
			}
		}
	}

	total_alg_count.total += count;
	total_alg_count.failed += fail_count;

	clock_gettime(CLOCK_MONOTONIC, &end);

	elapsed = (end.tv_sec - st.tv_sec) + 
	                 (end.tv_nsec - st.tv_nsec) / 1000000000.0;

	flockfile(stderr);
	fprintf(stderr, "thread: %2d", tid); 
	fprintf(stderr, " %8.2f sec", elapsed); 
	fprintf(stderr, "              DES: %5d", alg_c.des); 
	fprintf(stderr, "               NT: %5d", alg_c.nt); 
	fprintf(stderr, "              MD5: %5d", alg_c.md5); 
	fprintf(stderr, "           SHA256: %5d", alg_c.s256); 
	fprintf(stderr, "           SHA512: %5d", alg_c.s512); 
	fprintf(stderr, "         YESCRYPT: %5d", alg_c.y); 
	fprintf(stderr, "    GOST_YESCRYPT: %5d", alg_c.gh);  
	fprintf(stderr, "           BCRYPT: %5d", alg_c.bcry); 
	fprintf(stderr, "  total: %8d", count); 
	fprintf(stderr, "  failed: %8d\n", fail_count);
	funlockfile(stderr);
	pthread_exit(EXIT_SUCCESS);
}

/*
typedef struct {
	int des;
	int nt;
	int md5;
	int s256;
	int s512;
	int y;
	int gh;
	int bcry;	
} al_count_t;
*/
/*
void algo_counter(char * hash, al_count_t * alg_c){
	if(strcmp(hash, "DES") == 0) { alg_c->des++;};
	if(strcmp(hash, "y") == 0) { alg_c->y++;};
	if(strcmp(hash, "2b") == 0) { alg_c->bcry++;};	
	if(strcmp(hash, "gy") == 0) { alg_c->gh++; };
	if(strcmp(hash, "6") == 0) { alg_c->s512++; };
	if(strcmp(hash, "5") == 0) { alg_c->s256++; };
	if(strcmp(hash, "1") == 0) { alg_c->md5++; };
	if(strcmp(hash, "3") == 0) { alg_c->nt++; };
}
*/

char * get_algo(char * hash){
	char * algo = NULL;
	char * hashcopy = malloc(sizeof(char*) * strlen(hash));
	strcpy(hashcopy, hash);
	
	if(hash[0] != '$'){
		free(hashcopy);
		algo = "DES";	
		return algo;
	}	

	algo = strtok(hashcopy, "$");
	free(hashcopy);
	return algo;
} 

void getHashType(char *hash, al_count_t * alg_c) {
    if (strncmp(hash, "$y$", 3) == 0) {
        alg_c->y++;
		total_alg_count.y++;
    } else if (strncmp(hash, "$1$", 3) == 0) {
        alg_c->md5++;
		total_alg_count.md5++;
    } else if (strncmp(hash, "$2b$", 2) == 0) {
        alg_c->bcry++;
		total_alg_count.bcry++;
    } else if (strncmp(hash, "$3", 2) == 0) {
        alg_c->nt++;
		total_alg_count.nt++;
    } else if (strncmp(hash, "$5$", 3) == 0) {
        alg_c->s256++;
		total_alg_count.s256++;
    } else if (strncmp(hash, "$6$", 3) == 0) {
        alg_c->s512++;
		total_alg_count.s512++;
    } else if (strncmp(hash, "$gy$", 4) == 0) {
        alg_c->gh++;
		total_alg_count.gh++;
    } else if (hash[0] != '$') {
        alg_c->des++;
		total_alg_count.des++;
    }
}

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
	passwd_arr = malloc(MAX_LIST_SIZE * sizeof(char *));
	if(!passwd_arr){
		perror("malloc");
		return NULL;	
	}

	while(fgets(buff, sizeof(buff), fp) != NULL && i < MAX_LIST_SIZE) {
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
		++i;
	}			
	pass_count = i;
	return passwd_arr;
}

char ** getHashes(FILE *fp){
	char buff[BUFFER];
	int i = 0;
	hash_arr = malloc(MAX_LIST_SIZE * sizeof(char *));
	if(!hash_arr){
		perror("malloc");
		return NULL;	
	}
	if(verbose) { printf("PRE loop in getHashes(FILE *fp)\n"); }
	while(fgets(buff, sizeof(buff), fp) != NULL && i < MAX_LIST_SIZE) {
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

bool crack(char *pass, char* hash){
	struct crypt_data data;
	char * res = NULL;
	data.initialized = 0;

	res = crypt_r(pass, hash, &data);
	if(res && strcmp(res, hash) == 0) {
		return true;
	}	
	return false;	
}
