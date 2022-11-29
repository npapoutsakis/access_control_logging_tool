#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], 1, strlen(filenames[i]), file);
			// printf("Bytes written: %ld\n", bytes);
			fclose(file);
		}
	
	}

	// for (i = 0; i < 10; i++) {

	// 	file = fopen(filenames[i], "a");
	// 	if (file == NULL) 
	// 		printf("fopen error\n");
	// 	else {
	// 		bytes = fwrite(filenames[i], 1, strlen(filenames[i]), file);
	// 		// printf("Bytes written: %ld\n", bytes);
	// 		fclose(file);
	// 	}

	// }

	// char *message = "Bye";

	// file = fopen(filenames[0], "a+");

	// fwrite(message, 1, strlen(message), file);

	// fclose(file);

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return 0;
}
