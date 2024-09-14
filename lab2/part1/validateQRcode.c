#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "lib/sha1.h"

#define SECRET_MAX_LENGTH 20
#define TOTP_LENGTH 6
#define TIME_STEP 30
#define DIGITS_POWER 1000000
#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCK_SIZE 64

// Convert hexadecimal string to binary data
uint8_t* hex_string_to_binary(const char *hex_string, size_t *binary_length) {
    size_t len = strlen(hex_string);
    *binary_length = len / 2;

    uint8_t *binary_data = (uint8_t*)malloc(*binary_length);
    if (!binary_data) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i < len; i += 2) {
        sscanf(&hex_string[i], "%2hhX", &binary_data[i / 2]);
    }

    return binary_data;
}
void reverse_data(uint8_t *data, size_t length) {
    size_t start = 0;
    size_t end = length - 1;
    uint8_t temp;

    while (start < end) {
        // Swap elements at start and end positions
        temp = data[start];
        data[start] = data[end];
        data[end] = temp;

        // Move to the next pair of elements
        start++;
        end--;
    }
}

// Calculate HMAC-SHA1 hash
void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *digest) {
    SHA1_INFO ctx;
    uint8_t k_ipad[SHA1_BLOCK_SIZE], k_opad[SHA1_BLOCK_SIZE];
    memset(k_ipad, 0, SHA1_BLOCK_SIZE);
    memset(k_opad, 0, SHA1_BLOCK_SIZE);

    uint8_t inner_hash[SHA1_DIGEST_LENGTH];

    reverse_data(data, data_len);

//    printf("_______________hmac_sha1_______________\n");
//    printf("key: ");
//    for(int i = 0; i < key_len; i++)
//        printf("%d,",key[i]);
//    printf("\n");
//    printf("key_len: %d\n", key_len);
//    printf("data_len: %d\n", data_len);
//    for(int i = 0; i < data_len; i++)
//        printf("%d, ", data[i]);
//    printf("\n");

    // Copy the key into inner and outer pads
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    // XOR key with inner and outer pads
    for (size_t i = 0; i < SHA1_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
//    printf("key_in: ");
//    for(int i = 0; i < SHA1_BLOCK_SIZE; i++)
//        printf("%d,",k_ipad[i]);
//    printf("\n");
//    printf("key_out: ");
//    for(int i = 0; i < SHA1_BLOCK_SIZE; i++)
//        printf("%d,",k_opad[i]);
//    printf("\n");

    // Calculate inner hash: SHA1(k_ipad || data)
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner_hash);

//    printf("inner_hash: ");
//    for(int i = 0; i < SHA1_DIGEST_LENGTH; i++)
//        printf("%d, ", inner_hash[i]);
//    printf("\n");

    // Calculate outer hash: SHA1(k_opad || inner_hash)
    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, SHA1_BLOCK_SIZE);
    sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx, digest);

//    printf("outer_hash: ");
//    for(int i = 0; i < SHA1_DIGEST_LENGTH; i++)
//        printf("%d, ", digest[i]);
//    printf("\n");
}

// Calculate time-based one-time password
uint32_t generateTOTP(const uint8_t *secret, size_t secret_len, time_t timestamp) {
    // Calculate the time step corresponding to the timestamp
    uint64_t time_step = (timestamp - 0) / TIME_STEP;

    // Use HMAC-SHA1 algorithm to compute the hash
    uint8_t hmac_result[SHA1_DIGEST_LENGTH];


//    printf("time_stamp: %u\n", (unsigned int)timestamp);
//    printf("time_step: %8x\n", time_step);
//    printf("time_step_len: %zu\n", sizeof(time_step));
//
//    printf("secret key[0]: %x\n", secret[0]);
//    printf("secret_len: %u\n", secret_len);

    hmac_sha1(secret, secret_len, (const uint8_t *)&time_step, sizeof(uint64_t), hmac_result);

    // Calculate the dynamic code
    uint32_t offset = hmac_result[SHA1_DIGEST_LENGTH - 1] & 0xf;
    uint32_t dynamic_code = (hmac_result[offset] & 0x7f) << 24 |
                            (hmac_result[offset + 1] & 0xff) << 16 |
                            (hmac_result[offset + 2] & 0xff) << 8 |
                            (hmac_result[offset + 3] & 0xff);
    dynamic_code %= DIGITS_POWER;

    return dynamic_code;
}

// Validate TOTP value
int validateTOTP(const char *secret_hex, const char *TOTP_string) {
    // Convert hexadecimal key to binary
    size_t binary_length;
    uint8_t *binary_secret = hex_string_to_binary(secret_hex, &binary_length);

//    for(int i = 0; i < 10; i++)
//        printf("%d, ", binary_secret[i]);
//    printf("\n");

    // Convert TOTP value to unsigned integer
    uint32_t provided_totp = strtoul(TOTP_string, NULL, 10);

    // Get current timestamp
    time_t current_time;
    time(&current_time);


    // Generate TOTP value
    uint32_t generated_totp = generateTOTP(binary_secret, binary_length, current_time);

    // Validate TOTP value
    free(binary_secret); // Free dynamically allocated memory
//    printf("\n");
//    printf("hmac: %u\n", generated_totp);


    return (provided_totp == generated_totp) ? 1 : 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s [secretHex] [TOTP]\n", argv[0]);
        return 1;
    }

    char *secret_hex = argv[1];
    char *TOTP_value = argv[2];

    assert(strlen(secret_hex) <= SECRET_MAX_LENGTH * 2); // Check if the length of the secret key is valid
    assert(strlen(TOTP_value) == TOTP_LENGTH); // Check if the length of the TOTP value is valid

    printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
           secret_hex,
           TOTP_value,
           validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

    return 0;
}