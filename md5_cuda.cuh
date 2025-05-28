#ifndef MD5_CUDA_H
#define MD5_CUDA_H

#include <stdint.h>
#include <stddef.h>

// Maximum password length supported
#define MD5_MAX_INPUT 20
// We only ever need one 512-bit chunk (64 bytes) + 8 bytes length = 64 bytes total
#define CHUNK_SIZE 64

// 32-bit left rotation by n bits
#define ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

// Per-round shift amounts
__constant__ uint32_t SHIFT[64] = {
	7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
	5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
	4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
	6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

// K function constants
__constant__ uint32_t K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/**
 * device MD5 for inputs <= MD5_MAX_INPUT.
 * Pads to exactly one 512-bit chunk, then processes it.
 * Writes 16-byte digest into 'output' (little-endian).
 */
__device__ void md5_compute_cuda(
		const uint8_t *input, // pointer to input bytes
		size_t input_len, // length of input
		uint8_t *output // buffer that will have the 16 byte digest
		) {
	// 1) Initialize state (A, B, C, D) 
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xefcdab89;
	uint32_t h2 = 0x98badcfe;
	uint32_t h3 = 0x10325476;

	// 2) Build one 512-bit chunk in local memory
	uint8_t chunk[CHUNK_SIZE];
	// Copy input data into the chunk
	for (size_t i = 0; i < input_len; i++) {
		chunk[i] = input[i];
	}
	// Append '1' bit (0x80)
	chunk[input_len] = 0x80;
	// then pad with 0's until 56B
	for (size_t i = input_len + 1; i < 56; i++) {
		chunk[i] = 0;
	}
	// Append original length in bits as 64-bit little-endian
	uint64_t bits = (uint64_t)input_len * 8;
	for (int i = 0; i < 8; i++) {
		chunk[56 + i] = (bits >> (8 * i)) & 0xFF;
	}

	// 3) Message schedule: sixteen 32-bit words
	uint32_t M[16];

	// Here we will break the chunk into 16 32 bit words
	#pragma unroll
	for (int i = 0; i < 16; i++) {
		int idx = 4 * i;
		M[i] = (uint32_t)chunk[idx]
			| ((uint32_t)chunk[idx + 1] << 8)
			| ((uint32_t)chunk[idx + 2] << 16)
			| ((uint32_t)chunk[idx + 3] << 24);
	}

	// 4) Main loop for process of each of the 64 steps 
	uint32_t A = h0, B = h1, C = h2, D = h3;

#pragma unroll
	for (int i = 0; i < 64; i++) {
		uint32_t F, g;
		// select non linear function F and index g
		if (i < 16) {
			F = (B & C) | ((~B) & D);
			g = i;
		} else if (i < 32) {
			F = (D & B) | ((~D) & C);
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			F = B ^ C ^ D;
			g = (3 * i + 5) % 16;
		} else {
			F = C ^ (B | (~D));
			g = (7 * i) % 16;
		}
		uint32_t tmp = D;
		D = C;
		C = B;
		// Compute A
		uint32_t sum = A + F + K[i] + M[g];

		// then rotate and add to B
		B = B + ROTATE_LEFT(sum, SHIFT[i]);
		A = tmp;
	}

	// 5) Add back to state
	h0 += A;
	h1 += B;
	h2 += C;
	h3 += D;

	// 6) Output digest (little-endian)
	memcpy(output + 0, &h0, 4);
        memcpy(output + 4, &h1, 4);
        memcpy(output + 8, &h2, 4);
        memcpy(output + 12,&h3, 4);
}

#endif

