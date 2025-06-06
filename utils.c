#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <time.h>

// Generate a random 16-byte UCID
void generate_ucid(char ucid[UCID_LENGTH]){
    if (RAND_bytes((unsigned char *)ucid, UCID_LENGTH) != 1) {
        fprintf(stderr, "Error: RAND_bytes() failed to generate UCID.\n");
        exit(EXIT_FAILURE);
    }
}

// Print UCID as hex string
void print_ucid(const char ucid[UCID_LENGTH]){
    printf("UCID: ");
    for(int i = 0; i < UCID_LENGTH; ++i){
        printf("%02X", (unsigned char)ucid[i]);
    }
    printf("\n");
}

// Return current UNIX timestamp
uint64_t get_timestamp(){
    return (uint64_t)time(NULL);
}
