#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>      // For clock_gettime
#include "md5.h"       // provides md5_compute(), MD5_MAX_INPUT

int main(int argc, char *argv[]) {
	// Record the start time
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	// Check that user provided an md5 hash
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <MD5 hash>\n", argv[0]);
		return 1;
	}

	// Verify it is a valid hash for md5sum
	const char *target_md5 = argv[1];
	if (strlen(target_md5) != 32) {
		fprintf(stderr, "Error: MD5 hash must be 32 hex digits\n");
		return 1;
	}

	// open the password list
	FILE *wordlist = fopen("small_rockyou2.txt", "r");
	// FILE *wordlist = fopen("first_million_lines.txt", "r");
	// FILE *wordlist = fopen("pwdCuda500.txt", "r");
	if (!wordlist) {
		perror("Error opening file");
		return 1;
	}

	// buffers:
	// Password: will have space for the max allowed input
	char password[MD5_MAX_INPUT + 2];  // room for newline + NUL
	uint8_t hash_out[16];              // raw 16-byte MD5 output
	char hash_str[33];                 // 32 hex chars + NUL

	printf("Beginning password cracking...\n");
	// read each line, hash it, and compare
	while (fgets(password, sizeof(password), wordlist)) {
		// strip trailing newline or carriage return (Some files already did this manually)
		// length of line
		size_t len = strlen(password);
		while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
			password[--len] = '\0';
		}

		// compute MD5 on cleaned password
		// password: input bytes:
		// len: # of valid characters to hash
		// hash_out: Our digest (output) where 16 byte result is stored
		md5_compute((uint8_t*)password, len, hash_out);

		// turn the 16-byte result into a hex string
		for (int i = 0; i < 16; i++) {
			sprintf(hash_str + 2*i, "%02x", hash_out[i]);
		}
		// null terminate str
		hash_str[32] = '\0';

		// check for a match
		if (strcmp(hash_str, target_md5) == 0) {
			printf("Cracked Password is: %s\n", password);
			fclose(wordlist);

			// Record end time and print elapsed
			clock_gettime(CLOCK_MONOTONIC, &end);
			double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
			printf("Execution time: %.7f seconds\n", elapsed);

			return 0;
		}
	}

	printf("Password not found!\n");
	fclose(wordlist);

	// Record end time and print elapsed
	clock_gettime(CLOCK_MONOTONIC, &end);
	double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
	printf("Execution time: %.7f seconds\n", elapsed);

	return 1;
}

