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

	// for (i = 0; i < 10; i++) 
	// {
	// 	file = fopen(filenames[i], "r");		//this should fail

	// 	file = fopen(filenames[i], "w+");

	// 	if (file == NULL) 
	// 	{
	// 		printf("fopen error 1\n");
	// 	}
	// 	else 
	// 	{
	// 		bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
	// 		fclose(file);
	// 	}

	// }

	FILE *file2;

	char filenames2[10][10] = {"file_WO_0", "file_WO_1", 
			"file_WO_2", "file_WO_3", "file_WO_4",
			"file_WO_5", "file_WO_6", "file_WO_7", 		
			"file_WO_8", "file_WO_9"};

	for (i = 0; i < 10; i++) 
	{
		//Create file_WO
		file2 = fopen(filenames2[i], "r");		//this should fail

		file2 = fopen(filenames2[i], "w+");

		if (file2 == NULL)
		{
			file2 = fopen(filenames2[i], "w");
		}

		if (file2 != NULL)
		{
			bytes = fwrite(filenames2[i], strlen(filenames2[i]), 1, file2);	
			fclose(file2);
		}
		
		file2 = fopen(filenames2[i], "r");
		
		//Change permissions to write only for this user
		chmod(filenames2[i], S_IWUSR);			

		file2 = fopen(filenames2[i], "r");	//This should fail

	}

//CREATE FILE, CHANGE ITS PERMISSIONS AND READ IT
/////////////////////////////////////////////////////////////////////////////////////

	// FILE *file3;

	// char filenames3[10][10] = {"file_RO_0", "file_RO_1", 
	// 		"file_RO_2", "file_RO_3", "file_RO_4",
	// 		"file_RO_5", "file_RO_6", "file_RO_7", 		
	// 		"file_RO_8", "file_RO_9"};

	// for (i = 0; i < 10; i++) 
	// {
	// 	//Create file_RO
	// 	file3 = fopen(filenames3[i], "r");		//this should fail

	// 	file3 = fopen(filenames3[i], "w+");

	// 	if (file3 == NULL)
	// 	{
	// 		file3 = fopen(filenames3[i], "r");
	// 	}

	// 	if (file3 != NULL)
	// 	{
	// 		bytes = fwrite(filenames3[i], strlen(filenames3[i]), 1, file3);
	// 	}

	// 	//Change permissions to read only for this user
	// 	chmod(filenames3[i], S_IRUSR);

	// 	file3 = fopen(filenames3[i], "r");

	// 	if (file3 != NULL)
	// 	{
	// 		bytes = fwrite(filenames3[i], strlen(filenames3[i]), 1, file3);	//This should fail
	// 	}

	// }

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
