#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <gmp.h>
#include "rsa_assign_1.h"

#define LOG_FILE "file_logging.log"

unsigned char* getFingerprint(char *path);
long getFileLength(FILE *file);

FILE *fopen(const char *path, const char *mode) 
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/*All usefull info for log file - entry struct*/
	unsigned int uid;
	int access_type = 0;
	int action_denied = 0;	
	
	time_t datetime; 
	
	char *filepath = NULL;
	unsigned char *hash = NULL;

	/*First, get the user id*/
	uid = (unsigned int)getuid();
	
	//Help at https://pubs.opengroup.org/onlinepubs/009695299/functions/access.html
	/*Find Access Type*/
	/*Check for read, write permissions and existance check*/
	int existance_check = access(path, F_OK);			//0 if success, -1 failure

	if(existance_check != -1) {
		access_type = 1; 				//Opening, file exists

		/*Now find if user has permission*/	
		int read_priviledge = access(path, R_OK);
		int write_priviledge = access(path, W_OK);

		if(!strcmp(mode, "r")){
			if(read_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;
		}
		else if(!strcmp(mode, "w") || !strcmp(mode, "a")){
			if(write_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;

			/*In case mode is w, and no denied action*/
			if(!strcmp(mode, "w") && action_denied == 0)
				access_type = 3;		//Deletion, mode w erases the content
		}
		else if(!strcmp(mode, "r+") || !strcmp(mode, "w+") || !strcmp(mode, "a+")){
			/*All modes require read & write permission*/
			if(write_priviledge != -1 && read_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;

			if(!strcmp(mode, "w+") && action_denied == 0)
				access_type = 3; 		//Deletion
		}
	}
	else {
		access_type = 0;				//Creation, file doesnt exist
		if(mode[0] == 'r')				//If mode is read and file doesnt exist
			action_denied = 1;			//Action Denied!
	}

	// Get the file path
	// Help at https://pubs.opengroup.org/onlinepubs/009696799/functions/realpath.html
	filepath = realpath(path, NULL); 	//max_size = NULL, no specific format

	/*Time&Date*/
	// https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.dinkum_en_c99/time.html
	datetime = time(NULL);
	struct tm timestamp = *localtime(&datetime);

	// printf("%d\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t\n", 
	//uid, path, timestamp.tm_mday, timestamp.tm_mon + 1, timestamp.tm_year + 1900, timestamp.tm_hour, timestamp.tm_min, timestamp.tm_sec, access_type, action_denied);


	//get the hash of file contents
	hash = getFingerprint(path);

	// update_logfile(uid, access_type, action_denied, filepath);
	

	/*Will return the original fopen(), after we've collected info*/
	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	return original_fwrite_ret;
}

unsigned char* getFingerprint(char *path){

	unsigned char* returnVal = NULL;

	MD5_CTX ctx;

	MD5_Init(&ctx);

	//need to find file length
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	FILE *file = (*original_fopen)(path, "r");

	long size = getFileLength(file);

	// size=-1 -> file cant be opened
	if(size > 0){
		unsigned char file_content[size];
		fread(file_content, size, 1, file);				//read all content-> size bytes
		MD5_Update(&ctx, file_content, size);
		MD5_Final(returnVal, &ctx);
	}
	else if(size == -1)
		exit(-1);

	fclose(file);
	return returnVal;
}

long getFileLength(FILE *file){

	long fileLength = -1;

	if(file != NULL) {
		fseek(file, 0, SEEK_END);
		fileLength = ftell(file);
		fseek(file, 0, SEEK_SET);
	}

	return fileLength;
}

/*Update Log File every time an event happend*/
void update_logfile(unsigned int uid, int accessType, int denied, int path){
	//decrypt()		




	//encrypt()
	return;
}