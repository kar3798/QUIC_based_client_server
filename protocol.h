#ifndef CHAT_APP_PROTOCOL_H
#define CHAT_APP_PROTOCOL_H

#include <stdint.h>

#define PROTOCOL_VERSION 0x0100

// Message Types
#define MSG_TYPE_CONTROL  0x01
#define MSG_TYPE_TEXT     0x02
#define MSG_TYPE_ERROR    0x03
#define MSG_TYPE_ACK      0x04

// Control Subtypes
#define CTRL_LOGIN   0x10
#define CTRL_LOGOUT  0x11
#define CTRL_HISTORY 0x12
#define CTRL_ONLINE  0x13

#define UCID_LENGTH 16
#define MAX_MESSAGE_SIZE 512

// Header for Chat Message
typedef struct {
    uint16_t version;
    uint8_t msg_type;
    uint8_t reserved;
    uint32_t length;
    uint32_t msg_id;
    uint32_t user_id;
    char ucid[UCID_LENGTH];
    uint64_t timestamp;
} ChatMessageHeader;

// Login payload
typedef struct {
    char username[32];
    char password[32];
} LoginPayload;

// Text message payload
typedef struct {
    char ucid[UCID_LENGTH];
    char message[MAX_MESSAGE_SIZE];
} TextPayload;

// Function declarations for protocol utilities
void build_header(ChatMessageHeader* header,
                  uint8_t msg_type,
                  uint32_t msg_id,
                  uint32_t user_id,
                  const char* ucid,
                  uint32_t payload_length);

void serialize_header(const ChatMessageHeader* header, uint8_t* buffer);
void deserialize_header(const uint8_t* buffer, ChatMessageHeader* header);

#endif //CHAT_APP_PROTOCOL_H

