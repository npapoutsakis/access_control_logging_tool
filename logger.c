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

#define LOG_FILE "./file_logging.log"
#define MAX_PATH_LENGTH 100

void update_logfile(unsigned int uid, const char *path, struct tm timeInfo, int accessType, int denied, unsigned char *hash);
char *getPathFromStream(FILE *file);
unsigned char* getFingerprint(const char *path);
long getFileLength(FILE *file);

FILE *fopen(const char *path, const char *mode) 
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);


	/*All usefull info for log file - entry struct*/
	unsigned int uid = 0;
	int access_type = 0;
	int action_denied = 0;
	
	time_t date_time;
	struct tm timestamp;
	char *filepath = NULL;
	
	unsigned char *hash = {0};

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

		if(strcmp(mode, "r") == 0){
			if(read_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;
		}
		else if(strcmp(mode, "w") == 0 || strcmp(mode, "a") == 0){
			if(write_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;

			/*In case mode is w, and no denied action*/
			if(strcmp(mode, "w")==0 && action_denied == 0)
				access_type = 3;		//Deletion, mode w erases the content
		}
		else if(strcmp(mode, "r+") == 0 || strcmp(mode, "w+") == 0 || strcmp(mode, "a+") == 0){
			/*All modes require read & write permission*/
			if(write_priviledge != -1 && read_priviledge != -1)
				action_denied = 0;
			else
				action_denied = 1;

			if(strcmp(mode, "w+") == 0 && action_denied == 0)
				access_type = 3; 		//Deletion
		}
	}
	else {
		access_type = 0;				//Creation, file doesnt exist
		if(mode[0] == 'r')				//If mode is read and file doesnt exist
			action_denied = 1;			//Action Denied!
		//Basically fopen will return null
		//Might move the below part inside existance check
	}

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	//If the path is used for log file and keys then return
	FILE *file_logging = (*original_fopen)(LOG_FILE, "a");
	if (strcmp(path,"file_logging.log") == 0)
		return original_fopen_ret;
	if(strcmp(path,"public.key") == 0 || strcmp(path,"private.key") == 0)
		return original_fopen_ret;

	// Get the file path
	// Help at https://pubs.opengroup.org/onlinepubs/009696799/functions/realpath.html
	filepath = realpath(path, NULL); 	//max_size = NULL, no specific format

	/*Time&Date*/
	// https://www.qnx.com/developers/docs/6.5.0SP1.update/com.qnx.doc.dinkum_en_c99/time.html
	date_time = time(NULL);
	timestamp = *localtime(&date_time);

	if(original_fopen_ret != NULL && filepath != NULL){
		//get the hash of file contents
		hash = getFingerprint(path);

		//Update LogFile
		update_logfile(uid, filepath, timestamp, access_type, action_denied, hash);
	}
	else{
		if(filepath != NULL)
			update_logfile(uid, filepath, timestamp, access_type, action_denied, hash);
		else
			update_logfile(uid, path, timestamp, access_type, action_denied, hash);
	}

	/*Will return the original fopen(), after we've collected info*/
	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);


	/*All usefull info for log file - entry struct*/
	unsigned int uid = 0;
	int access_type = 0;
	int action_denied = 1;
	
	time_t date_time;
	struct tm timestamp;
	char *filepath = NULL;
	
	unsigned char *hash = NULL;

	/*First, get the user id*/
	uid = (unsigned int)getuid();

	/*Fwrite will modify the file*/
	access_type = 2;

	// Get the file path
	filepath = getPathFromStream(stream);

	int existance_check = access(filepath, F_OK);			//0 if success, -1 failure
	int write_priviledge = access(filepath, W_OK);			//Check for write permissions

	if(existance_check == 0){
		if(write_priviledge == 0)
			action_denied = 0;
	}
	
	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	/*Time&Date*/
	date_time = time(NULL);
	timestamp = *localtime(&date_time);

	//get the hash of file contents
	hash = getFingerprint(filepath);

	//Update LogFile
	update_logfile(uid, filepath, timestamp, access_type, action_denied, hash);

	/*Will return the original fwrite(), after we've collected info*/
	return original_fwrite_ret;
}

unsigned char* getFingerprint(const char *path){
	
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
		returnVal = (unsigned char *)malloc(size*sizeof(char));
		fread(file_content, 1, size, file);							//read all content-> size bytes
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
void update_logfile(unsigned int uid, const char *path, struct tm timeInfo, int accessType, int denied, unsigned char *hash){

	/* call the original fopen function */
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	//Open logFile to append the new entry
	FILE *logFile = (*original_fopen)(LOG_FILE, "a");	

	// printf("After opened log file!\n");

	if(logFile == NULL){
		printf("Log file didn't open!.....Something happend!\n");
		exit(-1);	
	}

	//If the file has content, then decrypt using private.key, else write the first content and encrypt using publiv.key	
	if((int)getFileLength(logFile) > 0){
		decryptData(LOG_FILE, "private.key", LOG_FILE);
	}

	fprintf(logFile, "%u\t%s\t%d-%d-%d\t%02d:%02d:%02d\t%d\t%d\t", uid, path, timeInfo.tm_mday, 
	timeInfo.tm_mon+1, timeInfo.tm_year+1900, timeInfo.tm_hour, timeInfo.tm_min, timeInfo.tm_sec, 
	accessType, denied);

	//write the hash
	if(hash != NULL){
		for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
			fprintf(logFile, "%02x", hash[i]);
			if(i == MD5_DIGEST_LENGTH - 1)
				fprintf(logFile, "\n");
		}
		free(hash);
	}
	else {
		for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
			fprintf(logFile, "%02x", 0);
			if(i == MD5_DIGEST_LENGTH - 1)
				fprintf(logFile, "\n");
		}		
	}

	fclose(logFile);

	//Encrypt the log file and return
	encryptData(LOG_FILE, "public.key", LOG_FILE);

	return;
}

char *getPathFromStream(FILE *file){

    char *temp = (char *)malloc(MAX_PATH_LENGTH);
    char *filename = (char *)malloc(MAX_PATH_LENGTH);
	
	//Concat, fileno() gives the file descriptor
    sprintf(temp, "/proc/self/fd/%d", fileno(file));

	//Returns the number of bytes
   	size_t read = readlink(temp, filename, MAX_PATH_LENGTH);

	//In case of failure -> return null
    if (read < 0)
        return NULL;

	//Null char
    filename[read] = '\0';
	free(temp);
    
	return filename;
}