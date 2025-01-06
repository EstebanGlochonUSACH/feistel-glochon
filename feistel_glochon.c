#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#define round_t uint8_t

// Constants
const size_t BLOCK_SIZE = 128UL;
const size_t HALF_BLOCK_SIZE = BLOCK_SIZE / 2UL;
const uint8_t INITIAL_KEY = 0b10010110;

size_t get_total_blocks(FILE *fp);

uint8_t circular_left_shift(uint8_t byte);
uint8_t generate_key(uint8_t base_key, round_t rounds);

uint8_t *apply_key_to_right_side(uint8_t *bytes, size_t size, uint8_t key);
uint8_t *apply_xor_to_left_side(uint8_t *lbytes, uint8_t *rbytes, uint8_t size);

uint8_t *clone_buffer(uint8_t *bytes, uint8_t size);
void copy_buffer(uint8_t *buffer, uint8_t *bytes, uint8_t size);

void init_encrypt(round_t rounds, const char *input_file, const char *output_file);
void init_decrypt(round_t rounds, const char *input_file, const char *output_file);
void feistel_encrypt(uint8_t *block, uint8_t *output, uint8_t key, round_t rounds);
void feistel_decrypt(uint8_t *block, uint8_t *output, uint8_t key, round_t rounds);

// void print_bytes(uint8_t *buffer, size_t length);

void *memset(void *s, int c, size_t len);

int main(int argc, char *argv[]) {
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <c|d> <rounds> <input_file> <output_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	char mode = argv[1][0];
	round_t rounds = (round_t)atoi(argv[2]);
	const char *input_file = argv[3];
	const char *output_file = argv[4];

	if (rounds < 1) {
		fprintf(stderr, "Invalid number of rounds: %d. It must be a value of 1 at minimum.\n", rounds);
		return EXIT_FAILURE;
	}
	else if (rounds > 8) {
		fprintf(stderr, "Invalid number of rounds: %d. It must be a value no more than 8.\n", rounds);
		return EXIT_FAILURE;
	}

	if (mode == 'c') {
		init_encrypt(rounds, input_file, output_file);
	} else if (mode == 'd') {
		init_decrypt(rounds, input_file, output_file);
	} else {
		fprintf(stderr, "Invalid mode: %c. Use 'c' for encryption or 'd' for decryption.\n", mode);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void init_encrypt(round_t rounds, const char *input_file, const char *output_file) {
	FILE *input = fopen(input_file, "rb");
	FILE *output = fopen(output_file, "wb");

	if (input == NULL) {
		perror("Input file error");
		exit(EXIT_FAILURE);
	}
	if (output == NULL) {
		fclose(input);
		perror("Output file error");
		exit(EXIT_FAILURE);
	}

	size_t blocks = get_total_blocks(input);

	uint8_t *buffer;
	uint8_t *encrypted;
	size_t buffer_size = (BLOCK_SIZE * sizeof(uint8_t));
	size_t bytes_read = 0;

	for(size_t i = 0; i < blocks; ++i){
		buffer = (uint8_t*)malloc(buffer_size);
		encrypted = (uint8_t*)malloc(buffer_size);
		bytes_read = fread(buffer, sizeof(uint8_t), buffer_size, input);
		if(bytes_read > 0){
			if(bytes_read < buffer_size){
				memset(buffer + bytes_read, 0, buffer_size - bytes_read);
			}
			feistel_encrypt(buffer, encrypted, INITIAL_KEY, rounds);
			// print_bytes(encrypted, buffer_size);
			fwrite(encrypted, sizeof(uint8_t), buffer_size, output);
		}
		free(buffer);
		free(encrypted);
	}
	fclose(input);
	fclose(output);
}

void feistel_encrypt(uint8_t *block, uint8_t *output, uint8_t key_0, round_t rounds) {
	size_t buffer_size = (HALF_BLOCK_SIZE * sizeof(uint8_t));
	uint8_t *left_prev = clone_buffer(block, buffer_size);
	uint8_t *right_prev = clone_buffer(block + buffer_size, buffer_size);
	uint8_t *left_curr = NULL;
	uint8_t *right_curr = NULL;
	uint8_t key_curr = key_0;

	for(round_t i = 0; i < rounds; ++i){
		key_curr = circular_left_shift(key_curr);
		right_curr = apply_key_to_right_side(right_prev, buffer_size, key_curr);
		left_curr = apply_xor_to_left_side(left_prev, right_curr, buffer_size);
		free(right_curr);
		right_curr = NULL;
		free(left_prev);
		left_prev = right_prev;
		right_prev = left_curr;
	}

	copy_buffer(output, right_prev, buffer_size);
	copy_buffer(output + buffer_size, left_prev, buffer_size);

	free(left_prev);
	free(right_prev);
}

void init_decrypt(round_t rounds, const char *input_file, const char *output_file) {
	FILE *input = fopen(input_file, "rb");
	FILE *output = fopen(output_file, "wb");

	if (input == NULL) {
		perror("Input file error");
		exit(EXIT_FAILURE);
	}
	if (output == NULL) {
		fclose(input);
		perror("Output file error");
		exit(EXIT_FAILURE);
	}

	size_t blocks = get_total_blocks(input);

	uint8_t *buffer;
	uint8_t *decrypted;
	size_t buffer_size = (BLOCK_SIZE * sizeof(uint8_t));
	size_t bytes_read = 0;
	size_t real_size = BLOCK_SIZE;

	for(size_t i = 0; i < blocks; ++i){
		buffer = (uint8_t*)malloc(buffer_size);
		decrypted = (uint8_t*)malloc(buffer_size);
		bytes_read = fread(buffer, sizeof(uint8_t), buffer_size, input);
		if(bytes_read == buffer_size){
			feistel_decrypt(buffer, decrypted, INITIAL_KEY, rounds);
			if(i == (blocks - 1)){
				while (real_size > 0 && decrypted[real_size - 1] == 0) --real_size;
				fwrite(decrypted, sizeof(uint8_t), real_size * sizeof(uint8_t), output);
			}
			else{
				fwrite(decrypted, sizeof(uint8_t), buffer_size, output);
			}
		}
		else{
			fprintf(stderr, "Invalid block size: %lu, expected: %lu", bytes_read, buffer_size);
			exit(EXIT_FAILURE);
		}
		free(buffer);
		free(decrypted);
	}
	fclose(input);
	fclose(output);
}

void feistel_decrypt(uint8_t *block, uint8_t *output, uint8_t key_0, round_t rounds) {
	size_t buffer_size = (HALF_BLOCK_SIZE * sizeof(uint8_t));
	uint8_t *left_prev = clone_buffer(block, buffer_size);
	uint8_t *right_prev = clone_buffer(block + buffer_size, buffer_size);
	uint8_t *left_curr = NULL;
	uint8_t *right_curr = NULL;
	uint8_t key_curr = key_0;

	for(round_t i = 0; i < rounds; ++i){
		key_curr = generate_key(key_0, rounds - i);
		right_curr = apply_key_to_right_side(right_prev, buffer_size, key_curr);
		left_curr = apply_xor_to_left_side(left_prev, right_curr, buffer_size);
		free(right_curr);
		right_curr = NULL;
		free(left_prev);
		left_prev = right_prev;
		right_prev = left_curr;
	}

	copy_buffer(output, right_prev, buffer_size);
	copy_buffer(output + buffer_size, left_prev, buffer_size);

	free(left_prev);
	free(right_prev);
}



size_t get_total_blocks(FILE *fp){
	fseek(fp, 0L, SEEK_END);
	size_t total_bytes = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	double fblocks = ceil((double)total_bytes / (double)BLOCK_SIZE);
	size_t blocks = (size_t)fblocks;
	return blocks;
}

uint8_t circular_left_shift(uint8_t byte) {
	return (byte << 1) | (byte >> 7);
}

uint8_t generate_key(uint8_t base_key, round_t rounds){
	uint8_t key = base_key;
	for(round_t i = 0; i < rounds; ++i) key = circular_left_shift(key);
	return key;
};

uint8_t *apply_key_to_right_side(uint8_t *bytes, size_t size, uint8_t key) {
	uint8_t *buffer = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (buffer == NULL) {
		perror("Memory allocation failed");
		exit(EXIT_FAILURE);
	}
	
	for (size_t i = 0; i < size; ++i) {
		buffer[i] = bytes[i] ^ key;
	}

	return buffer;
}

uint8_t *apply_xor_to_left_side(uint8_t *lbytes, uint8_t *rbytes, uint8_t size) {
	uint8_t *buffer = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (buffer == NULL) {
		perror("Memory allocation failed");
		exit(EXIT_FAILURE);
	}
	
	for (size_t i = 0; i < size; ++i) {
		buffer[i] = lbytes[i] ^ rbytes[i];
	}

	return buffer;
}

uint8_t *clone_buffer(uint8_t *bytes, uint8_t size) {
	uint8_t *buffer = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (buffer == NULL) {
		perror("Memory allocation failed");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < size; ++i) {
		buffer[i] = bytes[i];
	}

	return buffer;
}

void copy_buffer(uint8_t *buffer, uint8_t *bytes, uint8_t size) {
	for (size_t i = 0; i < size; ++i) {
		buffer[i] = bytes[i];
	}
}

// void print_bytes(uint8_t *buffer, size_t length){
// 	uint8_t _char;
// 	for(size_t i = 0; i < length; ++i){
// 		_char = buffer[i];
// 		if(_char >= 32 && _char <= 125){
// 			printf("[%03lu] 0b%02hhx %03d %c\n", i, _char, (int)_char, _char);
// 		}
// 		else{
// 			printf("[%03lu] 0b%02hhx %03d\n", i, _char, (int)_char);
// 		}
// 	}
// }

void *memset(void *s, int c, size_t len) {
	uint8_t* p = s;
	while(len--) *p++ = (uint8_t)c;
	return s;
}