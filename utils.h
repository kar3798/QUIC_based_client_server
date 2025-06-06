#ifndef CHAT_APP_UTILS_H
#define CHAT_APP_UTILS_H

#include <stdint.h>

#define UCID_LENGTH 16

// Generates a 16-byte UCID (UUID-style)
void generate_ucid(char ucid[UCID_LENGTH]);

// Prints the UCID in hex format
void print_ucid(const char ucid[UCID_LENGTH]);

// Returns current UNIX timestamp
uint64_t get_timestamp();

#endif //CHAT_APP_UTILS_H

