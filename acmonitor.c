#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <gmp.h>
#include "rsa_assign_1.h"

#define LOG_FILE "./file_logging.log"
#define MAX_LENGTH 150

struct entry
{

    int uid;           /* user id (positive integer) */
    int access_type;   /* access type values [0-2] */
    int action_denied; /* is action denied values [0-1] */

    time_t date; /* file access date */
    time_t time; /* file access time */

    char *file;        /* filename (string) */
    char *fingerprint; /* file fingerprint */
};

void usage(void)
{
    printf(
        "\n"
        "usage:\n"
        "\t./monitor \n"
        "Options:\n"
        "-m, Prints malicious users\n"
        "-i <filename>, Prints table of users that modified "
        "the file <filename> and the number of modifications\n"
        "-h, Help message\n\n");

    exit(0);
}

int isStoredFile(char filenames[][MAX_LENGTH], int lines, char *filename)
{
    for (int i = 0; i < lines; i++)
    {
        if (!strcmp(filenames[i], filename))
            return 1;
    }
    return 0;
}

int isStoredUser(int *users, int lines, int user_id)
{
    for (int i = 0; i < lines; i++)
    {
        if (users[i] == user_id)
            return 1;
    }
    return 0;
}

void list_unauthorized_accesses(FILE *log)
{
    // find the number of lines
    char c;
    int lines = 0;

    while ((c = getc(log)) != EOF)
    {
        if (c == '\n')
            lines++;
    }

    // Reset file pointer
    fseek(log, 0, SEEK_SET);

    // Construct the array of struct entry to store
    struct entry *entries = (struct entry *)malloc(lines * sizeof(struct entry));

    // Read each line of the log file and parsa the information
    ssize_t read;
    char *line;
    size_t line_len = 0;
    int index = 0;

    // https://man7.org/linux/man-pages/man3/getline.3.html
    while ((read = getline(&line, &line_len, log)) != -1)
    {

        entries[index].uid = atoi(strsep(&line, "\t"));

        entries[index].file = strsep(&line, "\t");

        entries[index].date = (time_t)strsep(&line, "\t");

        entries[index].time = (time_t)strsep(&line, "\t");

        entries[index].access_type = atoi(strsep(&line, "\t"));

        entries[index].action_denied = atoi(strsep(&line, "\t"));

        entries[index].fingerprint = strsep(&line, "");

        // Increase index and get the next line(log entry)
        index++;
    }

    // init an array to store the files names that had denied access
    char files[lines][MAX_LENGTH];
    memset(files, 0, lines * sizeof(char[MAX_LENGTH]));

    // Init an array filled with zeros for the users id.
    int users[lines];
    memset(users, 0, lines);

    // Flag that tells if the action was denied to the user
    int denied_flag = 0;

    // Flag thats tells if we found a malicious user
    int found = 0;

    // For each line, take the uid and compare
    for (int i = 0; i < lines; i++)
    {

        // get the uid of the user
        int userId = entries[i].uid;

        // for the entries
        for (int j = 0; j < lines; j++)
        {

            // if the action is denied by the specific id, increase flag
            if (userId == entries[j].uid && entries[j].action_denied == 1 && !isStoredFile(files, lines, entries[j].file))
            {

                denied_flag++;
                // Store the name of the file in buffer so that we cant print it afterwards
                strcpy(files[j], entries[j].file);
            }
        }

        // Print the malicious user, the number of malicious actions and the files that he's done that
        if (denied_flag >= 7 && !isStoredUser(users, lines, userId))
        {

            printf("UID %d tried to access %d files without permission!\n", userId, denied_flag);

            // Store the malicious user
            users[i] = userId;
            found = 1;
        }

        // Re-init
        denied_flag = 0;
    }

    if (!found)
        printf("No sus events!\n");

    free(entries);
    return;
}

void list_file_modifications(FILE *log, char *file_to_scan)
{
    // find the number of lines
    char c;
    int lines = 0;

    while ((c = getc(log)) != EOF)
    {
        if (c == '\n')
            lines++;
    }

    // Reset file pointer
    fseek(log, 0, SEEK_SET);

    // Construct the array of struct entry to store
    struct entry *entries = (struct entry *)malloc(lines * sizeof(struct entry));

    // Read each line of the log file and parsa the information
    ssize_t read;
    char *line;
    size_t line_len = 0;
    int index = 0;

    // https://man7.org/linux/man-pages/man3/getline.3.html
    while ((read = getline(&line, &line_len, log)) != -1)
    {

        entries[index].uid = atoi(strsep(&line, "\t"));

        entries[index].file = strsep(&line, "\t");

        entries[index].date = (time_t)strsep(&line, "\t");

        entries[index].time = (time_t)strsep(&line, "\t");

        entries[index].access_type = atoi(strsep(&line, "\t"));

        entries[index].action_denied = atoi(strsep(&line, "\t"));

        entries[index].fingerprint = strsep(&line, "");
        // Increase index and get the next line(log entry)
        index++;
    }
    
    // Init an array filled with zeros for the users id.
    int users[lines];
    memset(users, 0, lines);

    // Init modification array with zeros
    int modifications[lines];
    memset(modifications, 0, lines);

    // Declare current and previous hash to compare
    char current_hash[MD5_DIGEST_LENGTH];

    // Init space for hashes -> set to zero
    memset(&current_hash, 0, MD5_DIGEST_LENGTH);

    for (int i = 0; i < lines; i++) {

        if (entries[i].action_denied == 0 && isStoredUser(users, lines, entries[i].uid) == 0 && strcmp(entries[i].file, file_to_scan) == 0) {
            
            if (strcmp(entries[i].fingerprint, current_hash) != 0){
                // if new then rememeber the user and fingerprint to check in the next one
                users[i] = entries[i].uid;
                strcpy(current_hash, entries[i].fingerprint);
                modifications[i] = modifications[i] + 1;
            }
        }
        else if (entries[i].action_denied == 0 && isStoredUser(users, lines, entries[i].uid)){
            // i need to find the user that is in the table and update the modifications he has
            if(strcmp(entries[i].fingerprint, current_hash) != 0) {
                for (int j = 0; j < lines; j++) {
                    strcpy(current_hash, entries[i].fingerprint);
                    if(users[j] == entries[i].uid)
                        modifications[j] = modifications[j] + 1; // increase the modifications of the user by one
                }
            }
        }
    }

    free(entries);
    return;
}

int main(int argc, char *argv[])
{

    int ch;
    FILE *log;

    if (argc < 2)
        usage();

    // Decrypt the file before open
    decryptData(LOG_FILE, "private.key", LOG_FILE);

    log = fopen("./file_logging.log", "r");
    if (log == NULL)
    {
        printf("Error opening log file \"%s\"\n", "./log");
        return 1;
    }

    while ((ch = getopt(argc, argv, "hi:m")) != -1)
    {
        switch (ch)
        {
        case 'i':
            list_file_modifications(log, optarg);
            break;
        case 'm':
            list_unauthorized_accesses(log);
            break;
        default:
            usage();
        }
    }

    // Encrypt again so that the program remains functionall
    encryptData(LOG_FILE, "public.key", LOG_FILE);

    fclose(log);
    argc -= optind;
    argv += optind;

    return 0;
}

void encryptData(char const *inputfile, char const *keyfile, char const *output)
{

    // Import public key
    mpz_t key_n;
    mpz_t key_exponent;

    mpz_init(key_n);
    mpz_init(key_exponent);

    // Size of 8 bytes each
    size_t keyBuffer[2];

    // Open file for reading
    FILE *keyDir = fopen(keyfile, "r");

    if (keyDir == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    fread(&keyBuffer[0], sizeof(size_t), 1, keyDir);
    fread(&keyBuffer[1], sizeof(size_t), 1, keyDir);

    fclose(keyDir);

    // File read finished, import to mpz_t variables
    mpz_import(key_n, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[0]);
    mpz_import(key_exponent, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[1]);

    // We have successfully gained the key from file!

    // Encryption begins
    // plaintext.txt
    FILE *input = fopen(inputfile, "r");

    // we need to know the lenght of the plaintext -> specifically the number of bytes
    if (input == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    // Seek the end of the file
    fseek(input, 0, SEEK_END);
    size_t len = ftell(input);

    // Return to the start
    fseek(input, 0, SEEK_SET);

    // Read each character from the file and store it the buffer
    char bufferRead[len];
    for (int j = 0; j < len; j++)
    {
        fread(&bufferRead[j], 1, 1, input);
        // printf("%c\n", bufferRead[j]);
    }

    fclose(input);

    // printf("Lenght of file is %lu\n", len);

    FILE *encrypted_file = fopen(output, "w+");
    if (encrypted_file == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    // Buffer that will contain the encrypted text
    size_t ciphertext[len];

    // printf("Size of size_t array %ld\n", sizeof(ciphertext[0]));

    int i = 0;
    while (i < len)
    {

        mpz_t temp_char;
        mpz_init(temp_char);

        // Import the 1 byte character into mpz_t variable
        mpz_import(temp_char, 1, 1, sizeof(char), 0, 0, &bufferRead[i]);

        mpz_t encrypted_var;
        mpz_init(encrypted_var);

        // Perform the encryption
        mpz_powm(encrypted_var, temp_char, key_exponent, key_n);

        // Store the encrypted byte in ciphertext buffer
        mpz_export(&ciphertext[i], NULL, 1, sizeof(size_t), 0, 0, encrypted_var);

        // Write the encrypted text in file
        fwrite(&ciphertext[i], sizeof(size_t), 1, encrypted_file);

        // Increment
        i++;

        mpz_clears(temp_char, encrypted_var, NULL);
    }

    mpz_clears(key_exponent, key_n, NULL);
    fclose(encrypted_file);
    return;
}

void decryptData(char const *inputfile, char const *keyfile, char const *output)
{

    // Import public key
    mpz_t key_n;
    mpz_t key_exponent;

    mpz_init(key_n);
    mpz_init(key_exponent);

    // Size of 8 bytes each
    size_t keyBuffer[2];

    // Open file for reading
    FILE *keyDir = fopen(keyfile, "r");

    if (keyDir == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    fread(&keyBuffer[0], sizeof(size_t), 1, keyDir);
    fread(&keyBuffer[1], sizeof(size_t), 1, keyDir);

    fclose(keyDir);

    // File read finished, import to mpz_t variables
    mpz_import(key_n, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[0]);
    mpz_import(key_exponent, 1, 1, sizeof(size_t), 0, 0, &keyBuffer[1]);

    // We have successfully gained the key from file!

    // Decryption begins
    // ciphertext.txt
    FILE *input = fopen(inputfile, "r");

    // we need to know the lenght of the plaintext -> specifically the number of bytes
    if (input == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    // Seek the end of the file
    fseek(input, 0, SEEK_END);
    size_t len = ftell(input);
    fseek(input, 0, SEEK_SET);

    // Read each character from the file and store it the buffer
    size_t bufferRead[len / sizeof(size_t)];
    for (int j = 0; j < len / sizeof(size_t); j++)
    {
        fread(&bufferRead[j], sizeof(size_t), 1, input);
        // printf("%lu\n", bufferRead[j]);
    }

    fclose(input);

    // printf("Lenght of file is %lu\n", len);

    FILE *decrypted_file = fopen(output, "w+");
    if (decrypted_file == NULL)
    {
        printf("File directory does not exist!\n");
        exit(1);
    }

    // Buffer that will contain the decrypted text
    char plaintext[len / sizeof(size_t)];

    int i = 0;
    while (i < len / sizeof(size_t))
    {

        mpz_t temp_char;
        mpz_init(temp_char);

        // Import the 1 byte character into mpz_t variable
        mpz_import(temp_char, 1, 1, sizeof(size_t), 0, 0, &bufferRead[i]);

        mpz_t encrypted_var;
        mpz_init(encrypted_var);

        // Perform the encryption
        mpz_powm(encrypted_var, temp_char, key_exponent, key_n);

        // gmp_printf("%Zd\n", encrypted_var);

        // Store the decrypted byte in plaintext buffer
        mpz_export(&plaintext[i], NULL, 1, sizeof(char), 0, 0, encrypted_var);

        // printf("%ld\n", ciphertext[i]);

        // Write the encrypted text in file
        fwrite(&plaintext[i], sizeof(char), 1, decrypted_file);

        i++;

        mpz_clears(temp_char, encrypted_var, NULL);
    }

    mpz_clears(key_exponent, key_n, NULL);
    fclose(decrypted_file);
    return;
}