#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lib/encoding.h"

//convert string to hex number
uint8_t* hex_string_to_binary(const char *hex_string, size_t *binary_length);
int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
    char uri[] = "otpauth://totp/";
    char issuer_string[] = "?issuer=";
    char secrete_string[] = "&secret=";
    char period_string[] = "&period=30";

    size_t binary_length;
    uint8_t *binary_data = hex_string_to_binary(secret_hex, &binary_length);

    char *buf = (char*)malloc(32);
    if (!buf) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    //base-32 encoding
    base32_encode(binary_data, binary_length, (uint8_t *)buf, 32);
    
    int len = strlen(uri) + strlen(issuer_string) + strlen(secrete_string)
            + strlen(period_string) + strlen(issuer) + strlen(accountName) +
            strlen(buf);
    char final_uri[len];
    strcpy(final_uri, uri);
    strcat(final_uri, accountName);
    strcat(final_uri, issuer_string);
    strcat(final_uri, issuer);
    strcat(final_uri, secrete_string);
    strcat(final_uri, buf);
    strcat(final_uri, period_string);
    // printf("%s\n", final_uri);


	displayQRcode(final_uri);

	return (0);
}

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