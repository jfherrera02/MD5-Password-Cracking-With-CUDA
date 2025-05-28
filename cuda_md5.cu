#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <cuda_runtime.h>
#include "md5_cuda.cuh"          // provides md5_compute_cuda(), MD5_MAX_INPUT

// only passwords up to MD5_MAX_INPUT chars
#define MAX_PWD_LEN (MD5_MAX_INPUT)

// Each thread hashes one password and compares to target
__global__ void crack_md5_kernel(
		const char    *d_pwds,   // flattened array: count * MAX_PWD_LEN chars
		const int     *d_pwlen,  // lengths of each password
		const uint8_t *d_target, // 16-byte target digest
		int           *d_result, // -1 if none, else index of first match
		size_t         count
		) {
	// calculate current threads global idx
	size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	// ensure we do not go out of range
	// prevent threads from doing extra work
	if (idx >= count || *d_result != -1) return;

	// locate this thread’s password
	const uint8_t *pw = (const uint8_t*)(d_pwds + idx * MAX_PWD_LEN);

	int len = d_pwlen[idx];

	// buffer for MD5 digest (16 bytes)
	uint8_t digest[16];
	md5_compute_cuda(pw, len, digest);

	// compare digest to our target
#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (digest[i] != d_target[i]) {
			return; // no match
		}
	}

	// We have a match
	atomicCAS(d_result, -1, (int)idx);
}

// convert hex str to bytes
static bool parse_hex_digest(const char *hex, uint8_t out[16]) {
	if (strlen(hex) != 32) return false;
	for (int i = 0; i < 16; i++) {
		unsigned int b;
		if (sscanf(hex + 2*i, "%2x", &b) != 1) return false;
		out[i] = (uint8_t)b;
	}
	return true;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <MD5 hash>\n", argv[0]);
		return 1;
	}

	// parse target digest
	uint8_t target[16];
	if (!parse_hex_digest(argv[1], target)) {
		fprintf(stderr, "Error: invalid MD5 hash '%s'\n", argv[1]);
		return 1;
	}

	// load passwords from small_rockyou2.txt
	// const size_t capacity = 500000000;  // adjust to available memory (100M due to mem limits)
	const size_t capacity = 100000000;
	//const size_t capacity = 1000000;

	// Must beware of memory usage on system:
	char (*h_pwds)[MAX_PWD_LEN] = (char (*)[MAX_PWD_LEN])malloc(capacity * MAX_PWD_LEN);
	int  *h_pwlen = (int*)malloc(capacity * sizeof(int));
	if (!h_pwds || !h_pwlen) {
		fprintf(stderr, "Memory allocation failed\n");
		return 1;
	}

	// timing: start file read
	struct timespec start_read, end_read;
	clock_gettime(CLOCK_MONOTONIC, &start_read);

	// Now we can proceed with file
	//FILE *fp = fopen("pwdCuda500.txt", "r");
	//FILE *fp = fopen("first_million_lines.txt", "r");
	FILE *fp = fopen("small_rockyou2.txt", "r");
	if (!fp) {
		perror("fopen small_rockyou2.txt");
		return 1;
	}

	// create buffer for file line reading
	char buf[128];
	size_t count = 0;
	// read until EOF
	while (fgets(buf, sizeof(buf), fp) && count < capacity) {
		// strip CR/NL
		buf[strcspn(buf, "\r\n")] = '\0';
		int L = (int)strnlen(buf, MAX_PWD_LEN);
		// copy up to MAX_PWD_LEN, ensure NUL
		strncpy(h_pwds[count], buf, MAX_PWD_LEN);
		if (L >= MAX_PWD_LEN) h_pwds[count][MAX_PWD_LEN-1] = '\0';
		// save length
		h_pwlen[count] = L;
		count++;
	}
	fclose(fp);

	// timing: end file read
	clock_gettime(CLOCK_MONOTONIC, &end_read);
	float read_s = (end_read.tv_sec - start_read.tv_sec)
		+ (end_read.tv_nsec - start_read.tv_nsec) / 1e9;
	printf("File reading time: %.7f s (loaded %zu passwords)\n", read_s, count);

	// allocate device buffers
	char    *d_pwds; // List of passwords (plaintext)
	int     *d_pwlen; // length of password
	uint8_t *d_target; // our target
	int     *d_result; // result of search
	cudaMalloc(&d_pwds,   count * MAX_PWD_LEN);
	cudaMalloc(&d_pwlen,  count * sizeof(int));
	cudaMalloc(&d_target, 16 * sizeof(uint8_t));
	cudaMalloc(&d_result, sizeof(int));

	// copy data from host to GPU
	cudaMemcpy(d_pwds,   h_pwds,   count * MAX_PWD_LEN, cudaMemcpyHostToDevice);
	cudaMemcpy(d_pwlen,  h_pwlen,  count * sizeof(int), cudaMemcpyHostToDevice);
	cudaMemcpy(d_target, target,   16 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	// initialize result to -1
	int init = -1;
	cudaMemcpy(d_result, &init, sizeof(int), cudaMemcpyHostToDevice);

	// timing: start CUDA hashing
	cudaEvent_t start_hash, stop_hash;
	cudaEventCreate(&start_hash);
	cudaEventCreate(&stop_hash);
	cudaEventRecord(start_hash);

	// launch kernel
	int threads = 1024;
	int blocks  = (int)((count + threads - 1) / threads);

	//
	crack_md5_kernel<<<blocks, threads>>>(d_pwds, d_pwlen, d_target, d_result, count);
	cudaDeviceSynchronize();

	// stop the GPU timing and record it
	cudaEventRecord(stop_hash);
	cudaEventSynchronize(stop_hash);
	float hash_ms = 0.0;
	cudaEventElapsedTime(&hash_ms, start_hash, stop_hash);
	printf("CUDA hashing time: %.7f ms\n", hash_ms);

	// Finished timing so we can get rid of events
	cudaEventDestroy(start_hash);
	cudaEventDestroy(stop_hash);

	// get the result (index of found pwd)
	int match_idx = -1;
	cudaMemcpy(&match_idx, d_result, sizeof(int), cudaMemcpyDeviceToHost);

	if (match_idx >= 0) {
		printf("Found password: %s\n", h_pwds[match_idx]);
	} else {
		printf("Password not found.\n");
	}

	// cleanup
	free(h_pwds);
	free(h_pwlen);
	cudaFree(d_pwds);
	cudaFree(d_pwlen);
	cudaFree(d_target);
	cudaFree(d_result);

	return 0;
}

