#include "protocol.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// Build a standard PDU header
void build_header(ChatMessageHeader* header,
                  uint8_t msg_type,
                  uint32_t msg_id,
                  uint32_t user_id,
                  const char* ucid,
                  uint32_t payload_length) {
    header->version = PROTOCOL_VERSION;
    header->msg_type = msg_type;
    header->reserved = 0;
    header->length = payload_length;
    header->msg_id = msg_id;
    header->user_id = user_id;

    if (ucid) {
        memcpy(header->ucid, ucid, UCID_LENGTH);
    } else {
        memset(header->ucid, 0, UCID_LENGTH);
    }

    header->timestamp = (uint64_t)time(NULL);
}

// Serialize a header to raw bytes (for sending over the wire)
void serialize_header(const ChatMessageHeader* header, uint8_t* buffer) {
    memcpy(buffer, header, sizeof(ChatMessageHeader));
}

// Deserialize raw bytes into a header
void deserialize_header(const uint8_t* buffer, ChatMessageHeader* header) {
    memcpy(header, buffer, sizeof(ChatMessageHeader));
}

// Utility to print a header for debugging
void print_header(const ChatMessageHeader* header) {
    printf("Header:\n");
    printf("  Version: %x\n", header->version);
    printf("  Type: %u\n", header->msg_type);
    printf("  Length: %u bytes\n", header->length);
    printf("  Msg ID: %u\n", header->msg_id);
    printf("  User ID: %u\n", header->user_id);
    printf("  Timestamp: %llu\n", (unsigned long long)header->timestamp);
}

