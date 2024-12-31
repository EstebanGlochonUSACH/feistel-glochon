#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

// Constants
const size_t BLOCK_SIZE = 128;
const size_t HALF_BLOCK_SIZE = BLOCK_SIZE / 2;
const uint8_t INITIAL_KEY = 0b10010110;

size_t get_total_blocks(FILE *fp);

uint8_t circular_left_shift(uint8_t byte);
uint8_t generate_key(uint8_t base_key, int rounds);

uint8_t *apply_key_to_right_side(uint8_t *bytes, size_t size, uint8_t key);
uint8_t *apply_xor_to_left_side(uint8_t *lbytes, uint8_t *rbytes, uint8_t size);

uint8_t *clone_buffer(uint8_t *bytes, uint8_t size);
void copy_buffer(uint8_t *buffer, uint8_t *bytes, uint8_t size);

void init_encrypt(int rounds, const char *input_file, const char *output_file);
void init_decrypt(int rounds, const char *input_file, const char *output_file);
void feistel_encrypt(uint8_t *block, uint8_t *output, uint8_t key, int rounds);
void feistel_decrypt(uint8_t *block, uint8_t *output, uint8_t key, int rounds);

int main(int argc, char *argv[]) {
	if (argc != 5) {
		fprintf(stderr, "Usage: %s <c|d> <rounds> <input_file> <output_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	char mode = argv[1][0];
	int rounds = atoi(argv[2]);
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

void init_encrypt(int rounds, const char *input_file, const char *output_file) {
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

	for(size_t i = 0; i < blocks; ++i){
		buffer = (uint8_t*)calloc(BLOCK_SIZE, sizeof(uint8_t));
		encrypted = (uint8_t*)calloc(BLOCK_SIZE, sizeof(uint8_t));
		if(fread(buffer, sizeof(uint8_t), BLOCK_SIZE, input) > 0){
			feistel_encrypt(buffer, encrypted, INITIAL_KEY, rounds);
			fwrite(encrypted, sizeof(uint8_t), BLOCK_SIZE, output);
		}
		free(buffer);
		free(encrypted);
	}
	fclose(input);
	fclose(output);
}

void feistel_encrypt(uint8_t *block, uint8_t *output, uint8_t key_0, int rounds) {
	size_t buffer_size = (HALF_BLOCK_SIZE * sizeof(uint8_t));
	uint8_t *left_prev = clone_buffer(block, buffer_size);
	uint8_t *right_prev = clone_buffer(block + buffer_size, buffer_size);
	uint8_t *left_curr = NULL;
	uint8_t *right_curr = NULL;
	uint8_t key_curr = key_0;

	for(int i = 0; i < rounds; ++i){
		key_curr = generate_key(key_curr, i);
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

void init_decrypt(int rounds, const char *input_file, const char *output_file) {
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

	for(size_t i = 0; i < blocks; ++i){
		buffer = (uint8_t*)calloc(BLOCK_SIZE, sizeof(uint8_t));
		encrypted = (uint8_t*)calloc(BLOCK_SIZE, sizeof(uint8_t));
		if(fread(buffer, sizeof(uint8_t), BLOCK_SIZE, input) > 0){
			feistel_decrypt(buffer, encrypted, INITIAL_KEY, rounds);
			fwrite(encrypted, sizeof(uint8_t), BLOCK_SIZE, output);
		}
		free(buffer);
		free(encrypted);
	}
	fclose(input);
	fclose(output);
}

void feistel_decrypt(uint8_t *block, uint8_t *output, uint8_t key_0, int rounds) {
	size_t buffer_size = (HALF_BLOCK_SIZE * sizeof(uint8_t));
	uint8_t *left_prev = clone_buffer(block, buffer_size);
	uint8_t *right_prev = clone_buffer(block + buffer_size, buffer_size);
	uint8_t *left_curr = NULL;
	uint8_t *right_curr = NULL;
	uint8_t key_curr = key_0;

	for(int i = 0; i < rounds; ++i){
		key_curr = generate_key(key_curr, rounds - i);
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

uint8_t generate_key(uint8_t base_key, int rounds){
	uint8_t key = base_key;
	for(int i = 0; i < rounds; ++i) key = circular_left_shift(key);
	return key;
};

uint8_t *apply_key_to_right_side(uint8_t *bytes, size_t size, uint8_t key) {
	uint8_t *buffer = (uint8_t *)calloc(size, sizeof(uint8_t));
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
	uint8_t *buffer = (uint8_t *)calloc(size, sizeof(uint8_t));
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
