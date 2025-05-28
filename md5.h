#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Maximum input length support (All Passwords are fairly short) */
#define MD5_MAX_INPUT 20

/* Rotate a 32-bit value left by n bits */
#define MD5_ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Per-round shift amounts */
static const uint32_t MD5_SHIFT[64] = {
	7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
	5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
	4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
	6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

/* Sine-derived constants
 * 32 bit const
 */
static const uint32_t K[64] = {
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
 * Compute MD5 of input/password
 * and write the 16-byte digest into output hash
 */
static void md5_compute(const uint8_t *input, size_t input_len, uint8_t *output) {
	/* 1. Initialize hash state */
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xefcdab89;
	uint32_t h2 = 0x98badcfe;
	uint32_t h3 = 0x10325476;

	/* 2. Pre-processing (padding) */
	size_t padded_len = input_len + 1;
	while (padded_len % 64 != 56) padded_len++;
	uint8_t *msg = calloc(padded_len + 8, 1);
	memcpy(msg, input, input_len);
	msg[input_len] = 0x80;
	uint64_t bit_len = (uint64_t)input_len * 8;
	memcpy(msg + padded_len, &bit_len, 8);

	/* 3. Process each 512-bit chunk */
	for (size_t off = 0; off < padded_len; off += 64) {
		uint32_t M[16];
		for (int i = 0; i < 16; i++) {
			size_t idx = off + i * 4;
			M[i] = (uint32_t)msg[idx]
				| ((uint32_t)msg[idx+1] << 8)
				| ((uint32_t)msg[idx+2] << 16)
				| ((uint32_t)msg[idx+3] << 24);
		}

		uint32_t A = h0, B = h1, C = h2, D = h3;
		for (int i = 0; i < 64; i++) {
			uint32_t F, g;
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

			uint32_t temp = D;
			D = C;
			C = B;
			uint32_t sum = A + F + K[i] + M[g];
			B = B + MD5_ROTATE_LEFT(sum, MD5_SHIFT[i]);
			A = temp;
		}

		h0 += A;  h1 += B;  h2 += C;  h3 += D;
	}

	free(msg);

	/* 4. Output in little-endian */
	memcpy(output + 0, &h0, 4);
	memcpy(output + 4, &h1, 4);
	memcpy(output + 8, &h2, 4);
	memcpy(output + 12,&h3, 4);
}

#endif
