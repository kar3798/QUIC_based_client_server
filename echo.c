#ifdef _WIN32
//
// The conformant preprocessor along with the newest SDK throws this warning for
// a macro in C mode. As users might run into this exact bug, exclude this
// warning here. This is not an MsQuic bug but a Windows SDK bug.
//
#pragma warning(disable:5105)
#endif
#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>
// KAY
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include "protocol.h"
#include "utils.h"
#include <signal.h>

#include "quicpatch.h"
#include "quichelper.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = { "quicecho", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
// KAY Chat name modified
const QUIC_BUFFER Alpn = { sizeof("quicchat") - 1, (uint8_t*)"quicchat" };

//
// The UDP port used by the server side of the protocol.
//
const uint16_t UdpPort = 4567;

//
// The default idle timeout period (1 second) used for the protocol.
//
// KAY 60 seconds for chatClient connected
const uint64_t IdleTimeoutMs = 60000;

//
// The length of buffer sent over the streams in the protocol.
//
const uint32_t SendBufferLength = 100;

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

/*void PrintUsage()
{
    printf(
        "\n"
        "echo runs a simple client or server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  echo -client -unsecure -target:{IPAddress|Hostname} [-ticket:<ticket>]\n"
        "  echo -server -cert_hash:<...>\n"
        "  echo -server -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        );
}*/
// ==================================MY_DEFINITIONS_BEGIN==============================================
// KAY - Modified to include quit
void PrintUsage()
{
    printf(
        "\n"
        "chat runs a simple client or server chat application.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  chat -client -unsecure -target:{IPAddress|Hostname}\n"
        "  chat -server -cert_hash:<...>\n"
        "  chat -server -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        "\n"
        "Once connected:\n"
        "  - Type messages and press Enter to send\n"
        "  - Type 'quit' to exit\n"
        );
}

//
// Global connection handle for the client to send messages
//
HQUIC GlobalClientConnection = NULL;

//
// Global stream handle for continuous communication
//
HQUIC GlobalClientStream = NULL;

//
// Client credentials for login (temporary storage)
//
char GlobalClientUsername[32];
char GlobalClientPassword[32];
char GlobalClientUCID[UCID_LENGTH];

//
// Maximum message length
//
const uint32_t MaxMessageLength = 1024;

//
// Simple user database for authentication
//
typedef struct {
    const char* username;
    const char* password;
} User;

//
// Hardcoded users for prototype
//
const User users[] = {
    {"alice", "pass123"},
    {"bob", "pass456"},
    {"charlie", "pass789"}
};
const int user_count = sizeof(users) / sizeof(users[0]);

//
// Structure to track connected clients
//
typedef struct {
    HQUIC Stream;
    char username[32];
    char ucid[16]; 
    BOOLEAN authenticated;
    uint32_t user_id;
} ConnectedClient;

//
// Array to store connected clients (simple fixed-size for prototype)
//
#define MAX_CLIENTS 10
ConnectedClient connected_clients[MAX_CLIENTS];
int connected_client_count = 0;

//
// Validate user credentials
// Returns 1 if valid, 0 if invalid
//
int validate_user(const char* username, const char* password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0 &&
            strcmp(users[i].password, password) == 0) {
            return 1;  // Valid user
        }
    }
    return 0;  // Invalid credentials
}

//
// Find or add a client to the connected clients list
//
int add_authenticated_client(HQUIC Stream, const char* username) {
    // Find empty slot
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i].Stream == NULL) {
            connected_clients[i].Stream = Stream;
            strncpy(connected_clients[i].username, username, 31);
            connected_clients[i].username[31] = '\0';
            connected_clients[i].authenticated = TRUE;
            connected_clients[i].user_id = i + 1;
            generate_ucid(connected_clients[i].ucid);
            //printf("[DEBUG] Added user '%s' with stream %p at slot %d\n", username, Stream, i);
            
            printf("[Info] Added user '%s'\n", username);
            printf("[Info] Generated ");
            print_ucid(connected_clients[i].ucid);
            return i;
        }
    }
    return -1;  // No space
}

//
// Get username for a stream
//
const char* get_client_username(HQUIC Stream) {
    // printf("[DEBUG] Looking for stream %p\n", Stream);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i].Stream == Stream && 
            connected_clients[i].authenticated) {
            // printf("[DEBUG] Found user '%s'\n", connected_clients[i].username);
            return connected_clients[i].username;
        }
    }
    printf("[DEBUG] Stream not found in authenticated list\n");
    return "UNKNOWN";
}

//
// Sends a message over a QUIC stream
//
void
SendMessage(
    _In_ HQUIC Stream,
    _In_ const char* Message
    )
{
    size_t MessageLen = strlen(Message);
    if (MessageLen > MaxMessageLength - 1) {
        MessageLen = MaxMessageLength - 1;
    }
    
    // Allocate buffer for QUIC_BUFFER + message
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + MessageLen + 1);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        return;
    }
    
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = (uint32_t)MessageLen;
    memcpy(SendBuffer->Buffer, Message, MessageLen);
    SendBuffer->Buffer[MessageLen] = '\0';

    // Send the message (don't close the stream with FIN flag)
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
    }
}

//
// Send a PDU over a QUIC stream
//
void SendPDU(HQUIC Stream, const ChatMessageHeader* header, const void* payload) {
    // Calculate total size
    size_t total_size = sizeof(ChatMessageHeader) + header->length;
    
    // Allocate buffer for QUIC_BUFFER + header + payload
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + total_size);
    if (SendBufferRaw == NULL) {
        printf("[Error] SendPDU allocation failed!\n");
        return;
    }
    
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = (uint32_t)total_size;
    
    // Serialize header
    serialize_header(header, SendBuffer->Buffer);
    
    // Copy payload if present
    if (payload && header->length > 0) {
        memcpy(SendBuffer->Buffer + sizeof(ChatMessageHeader), payload, header->length);
    }
    
    // Send the PDU
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
        printf("[Error] PDU StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
    }
}

//
// Send a text message PDU
//
void SendTextPDU(HQUIC Stream, uint32_t msg_id, uint32_t user_id, 
                 const char* ucid, const char* message) {
    ChatMessageHeader header;
    TextPayload payload;
    
    // Prepare payload
    memset(&payload, 0, sizeof(payload));
    if (ucid) {
        memcpy(payload.ucid, ucid, UCID_LENGTH);
    }
    strncpy(payload.message, message, MAX_MESSAGE_SIZE - 1);
    payload.message[MAX_MESSAGE_SIZE - 1] = '\0';
    
    // Build header
    build_header(&header, MSG_TYPE_TEXT, msg_id, user_id, ucid, sizeof(TextPayload));
    
    // Send PDU
    SendPDU(Stream, &header, &payload);
}

//
// Send a login PDU
//
void SendLoginPDU(HQUIC Stream, const char* username, const char* password) {
    ChatMessageHeader header;
    LoginPayload payload;
    
    // Prepare payload
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.username, username, 31);
    payload.username[31] = '\0';
    strncpy(payload.password, password, 31);
    payload.password[31] = '\0';
    
    // Build header (no UCID yet since we're not authenticated)
    build_header(&header, MSG_TYPE_CONTROL, 1, 0, NULL, sizeof(LoginPayload));
    header.msg_type = MSG_TYPE_CONTROL;  // Make sure it's control type
    header.reserved = CTRL_LOGIN;  // Use reserved field for control subtype
    
    // Send PDU
    SendPDU(Stream, &header, &payload);
    
    printf("\n[CLIENT]: [Info] Sending LOGIN PDU...\n");
}

//
// Send an error PDU
//
void SendErrorPDU(HQUIC Stream, uint32_t error_code, const char* error_message) {
    ChatMessageHeader header;
    char payload[256];
    
    // Prepare error message
    memset(payload, 0, sizeof(payload));
    strncpy(payload, error_message, sizeof(payload) - 1);
    
    // Build header
    build_header(&header, MSG_TYPE_ERROR, error_code, 0, NULL, strlen(payload) + 1);
    
    // Send PDU
    SendPDU(Stream, &header, payload);
}

//
// Broadcast a message to all authenticated clients
//
void broadcast_message(const char* sender_username, const char* message, HQUIC sender_stream) {
    // char formatted_message[MaxMessageLength];
    // snprintf(formatted_message, sizeof(formatted_message), "[%s]: %s", sender_username, message);
    
    // Server message IDs start at 1000
    static uint32_t server_msg_id = 1000;
    
    
    
    // Send to all authenticated clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i].Stream != NULL && 
            connected_clients[i].authenticated) {
            // Send to everyone (including sender for confirmation)
            // SendMessage(connected_clients[i].Stream, formatted_message);
            // For system messages, use empty UCID
            const char* ucid_to_use = NULL;
            uint32_t user_id = 0;
            
            // If not a system message, find the sender's UCID
            if (sender_stream != NULL) {
                for (int j = 0; j < MAX_CLIENTS; j++) {
                    if (connected_clients[j].Stream == sender_stream) {
                        ucid_to_use = connected_clients[j].ucid;
                        user_id = connected_clients[j].user_id;
                        break;
                    }
                }
            }
            
            // Format message with sender name
            char formatted_msg[MAX_MESSAGE_SIZE];
            snprintf(formatted_msg, sizeof(formatted_msg), "[%s]: %s", sender_username, message);
            
            // Send as TEXT PDU
            SendTextPDU(connected_clients[i].Stream, server_msg_id++, user_id, 
                       ucid_to_use, formatted_msg);
        }
    }
}

//
// Remove a client when they disconnect
//
void remove_client(HQUIC Stream) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i].Stream == Stream) {
            if (connected_clients[i].authenticated) {
                // Broadcast leave message before removing
                char leave_msg[128];
                snprintf(leave_msg, sizeof(leave_msg), "*** %s has left the chat ***", 
                         connected_clients[i].username);
                
                // Clear this client first so they don't receive their own leave message
                char username[32];
                strncpy(username, connected_clients[i].username, 31);
                username[31] = '\0';
                
                connected_clients[i].Stream = NULL;
                connected_clients[i].authenticated = FALSE;
                connected_client_count--;
                
                // Now broadcast to remaining clients
                broadcast_message("SYSTEM", leave_msg, NULL);
                
                //printf("===============\n[SERVER]: ");
                fflush(stdout);
            } else {
                // Just remove unauthenticated client
                connected_clients[i].Stream = NULL;
                connected_client_count--;
            }
            break;
        }
    }
}

//
// Get list of online users
//
void get_online_users(char* buffer, size_t buffer_size) {
    int count = 0;
    buffer[0] = '\0';
    
    strcat(buffer, "*** Online users: ");
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i].Stream != NULL && 
            connected_clients[i].authenticated) {
            if (count > 0) strcat(buffer, ", ");
            strcat(buffer, connected_clients[i].username);
            count++;
        }
    }
    
    if (count == 0) {
        strcat(buffer, "No users online");
    }
    
    strcat(buffer, " ***");
}
// ==================================MY_DEFINITIONS_END==============================================
//
// Allocates and sends some data over a QUIC stream.
//
/* void
ServerSend(
    _In_ HQUIC Stream
    )
{
    //
    // Allocates and builds the buffer to send over the stream.
    //
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
} */

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        // printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        /*printf("[strm][%p] Data received\n", Stream);
        break;*/
        // KAY
        char ucid[16];
        // Process each buffer received
		for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
		
		    if (Event->RECEIVE.Buffers[i].Length >= sizeof(ChatMessageHeader)) {
		        ChatMessageHeader temp_header;
		        deserialize_header(Event->RECEIVE.Buffers[i].Buffer, &temp_header);
		       
		         if (temp_header.version == PROTOCOL_VERSION) {
			    if (temp_header.msg_type == MSG_TYPE_CONTROL && 
				temp_header.reserved == CTRL_LOGIN &&
				temp_header.length == sizeof(LoginPayload)) {
				
				LoginPayload login_payload;
				memcpy(&login_payload,
				       Event->RECEIVE.Buffers[i].Buffer + sizeof(ChatMessageHeader),
				       sizeof(LoginPayload));
				
				// Validate credentials
				if (validate_user(login_payload.username, login_payload.password)) {
				    printf("\n[Info]: User '%s' authenticated successfully\n[SERVER]: ", 
					   login_payload.username);
				    fflush(stdout);
				    
				    int slot = add_authenticated_client(Stream, login_payload.username);
				    
				    if (slot >= 0) {
					// Send LOGIN_SUCCESS PDU with UCID
					ChatMessageHeader header;
					build_header(&header, MSG_TYPE_ACK, 1, connected_clients[slot].user_id, 
						    connected_clients[slot].ucid, UCID_LENGTH);
					
					SendPDU(Stream, &header, connected_clients[slot].ucid);
					
					printf("[Info] Sent LOGIN_SUCCESS PDU with UCID\n");
					
					// Broadcast join message
					char join_msg[128];
					snprintf(join_msg, sizeof(join_msg), "*** %s has joined the chat ***", 
						login_payload.username);
					broadcast_message("SYSTEM", join_msg, NULL);
            			     }
            			 } else { 
            			 	printf("\n[Error]: Login failed for '%s'\n[SERVER]: ", login_payload.username);
            				fflush(stdout);
            				
            				SendErrorPDU(Stream, 401, "Login failed: Invalid username or password");
              			 }
            		}
            		}
		        
		        // If it's a valid PDU, handle it
		            if (temp_header.msg_type == MSG_TYPE_TEXT) {
		                TextPayload text_payload;
		                if (temp_header.length == sizeof(TextPayload)) {
		                    // Extract payload
            			    memcpy(&text_payload,
            			           Event->RECEIVE.Buffers[i].Buffer + sizeof(ChatMessageHeader),
                   			   sizeof(TextPayload));
                   	            const char* username = get_client_username(Stream);
            			    if (strcmp(username, "UNKNOWN") != 0) {
                                    printf("[%s] - %s\n[SERVER]: ", username, text_payload.message);
                                    fflush(stdout);
                                    
                                    // Broadcast the message
                		    broadcast_message(username, text_payload.message, Stream);
            			} else {
            				printf("\n[UNAUTHENTICATED]: PDU Message rejected\n[SERVER]: ");
                			fflush(stdout);
                			// TODO: Send ERROR PDU back
            			}
			}
			} else {
		            // For now, just skip PDU processing
		            printf("[Info] Received PDU type %d\n[SERVER]: ", temp_header.msg_type);
		            fflush(stdout);
		           }
		            continue;  // Skip to next buffer
            	    }	
		    char Message[MaxMessageLength];
		    uint32_t Length = Event->RECEIVE.Buffers[i].Length;
		    if (Length >= MaxMessageLength) {
		        Length = MaxMessageLength - 1;
		    }
		    memcpy(Message, Event->RECEIVE.Buffers[i].Buffer, Length);
		    Message[Length] = '\0';
		    
		    // Check if this is a login message
            	    if (strncmp(Message, "LOGIN:", 6) == 0) {
            	        // Parse login credentials
                        char username[32] = {0};
                        char password[32] = {0};
                        
                         // Simple parsing of LOGIN:username:password
                         char* userStart = Message + 6;
                         char* passStart = strchr(userStart, ':');
                         
                          if (passStart != NULL) {
                              *passStart = '\0';  // Null terminate username
                              passStart++;  // Move to password
                              
                              strncpy(username, userStart, sizeof(username) - 1);
                    	      strncpy(password, passStart, sizeof(password) - 1);
                    	      
                    	      // Validate credentials
                    	      if (validate_user(username, password)) {
                    	         printf("\n[Info]: User '%s' authenticated successfully\n[SERVER]: ", username);
                                 fflush(stdout);                
    				 int slot = add_authenticated_client(Stream, username);
    				 
			                                      
                                 // Send success response
                                 //SendMessage(Stream, "LOGIN_SUCCESS");
                                 
                                 if (slot >= 0) {
				    // Send LOGIN_SUCCESS PDU with UCID
				    ChatMessageHeader header;
				    build_header(&header, MSG_TYPE_ACK, 1, connected_clients[slot].user_id, 
					     connected_clients[slot].ucid, UCID_LENGTH);
				
				    // Send header with UCID as payload
				    SendPDU(Stream, &header, connected_clients[slot].ucid);
				
				    printf("[Info] Sent LOGIN_SUCCESS PDU with UCID\n");
			         }
                                 
                                 // Broadcast join message to all clients
				 char join_msg[128];
				 snprintf(join_msg, sizeof(join_msg), "*** %s has joined the chat ***", username);
				 broadcast_message("",join_msg, NULL);
                              } else {
                                 printf("\n[SERVER]: Login failed for '%s'\n[SERVER]: ", username);
                                 fflush(stdout);
                                 
                                 
                                 
                                 // Store authenticated client
                                 add_authenticated_client(Stream, username);
                                 
                                 // Send failure response
                                 SendMessage(Stream, "LOGIN_FAILED");
                              }
                            } else {
                                SendMessage(Stream, "LOGIN_FAILED:Invalid format");
                            }
                         } else {
                                 
		            // Regular message - show with username
		            const char* username = get_client_username(Stream);
		            if (strcmp(username, "UNKNOWN") == 0){
		                printf("\n[UNAUTHENTICATED]: Message rejected\n[SERVER]: ");
        			fflush(stdout);
        			SendMessage(Stream, "ERROR: Please login first");
        		    } else {   
			    printf("[%s] - %s\n[SERVER]: ",username, Message);
			    fflush(stdout);
			    
			    // Echo the message back to confirm receipt
			    /*char Response[MaxMessageLength];
			    snprintf(Response, sizeof(Response), "Server received: %s", Message);
			    SendMessage(Stream, Response);*/
			    // Broadcast to all clients instead of echo
        		    broadcast_message(username, Message, Stream);
			}
		    }	
		}
   	break;    	
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        // printf("[strm][%p] Peer shut down\n", Stream);
        // ServerSend(Stream);
        // MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        //printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        const char* username = get_client_username(Stream);
        remove_client(Stream);
        printf("%s All done\n", username);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        /*printf("[conn][%p] Connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;*/
        // KAY
        // Modified to match DFA
        printf("[Info] Client connected - State: INIT\n");
    	fflush(stdout);
    	break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        //printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        printf("[Info] Client disconnected - State: DISCON\n");
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        // printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[Info]: Client stream established - waiting for AUTH");
        // printf("[SERVER]: Client stream established - STATE <AUTH TO BE COMPLETE>\n", Event->PEER_STREAM_STARTED.Stream);
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN
ServerLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    // KAY PeerBidiStreamCount from 1 to 10 to allow multiple streams
    Settings.PeerBidiStreamCount = 10;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    const char* Cert;
    const char* KeyFile;
    if ((Cert = GetValue(argc, argv, "cert_hash")) != NULL) {
        //
        // Load the server's certificate from the default certificate store,
        // using the provided certificate hash.
        //
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Config.CertHash.ShaHash),
                Config.CertHash.ShaHash);
        if (CertHashLen != sizeof(Config.CertHash.ShaHash)) {
            return FALSE;
        }
        Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Config.CredConfig.CertificateHash = &Config.CertHash;

    } else if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
               (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
        //
        // Loads the server's certificate from the file.
        //
        const char* Password = GetValue(argc, argv, "password");
        if (Password != NULL) {
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        } else {
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }

    } else {
        printf("Must specify ['-cert_hash'] or ['cert_file' and 'key_file' (and optionally 'password')]!\n");
        return FALSE;
    }

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the server side of the protocol.
//
void
RunServer(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;
    // KAY
    char Input[1024];
    memset(connected_clients, 0, sizeof(connected_clients));
    connected_client_count = 0;

    //
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    //
    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);
 
    //
    // Load the server configuration based on the command line.
    //
    if (!ServerLoadConfiguration(argc, argv)) {
        return;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    /*printf("Press Enter to exit.\n\n");
    getchar();*/
    // KAY
    //
	// Continue listening for connections and handle server input
	//
	printf("Server is listening on port %d. Type 'quit' to exit.\n", UdpPort);
	printf("[SERVER]: ");
	fflush(stdout);

	while (1) {
	    if (fgets(Input, sizeof(Input), stdin) != NULL) {
		// Remove newline
		Input[strcspn(Input, "\n")] = '\0';
		
		// Skip empty inputs
		if (strlen(Input) == 0) {
		    printf("[SERVER]: ");
		    fflush(stdout);
		    continue;
		}
		
		if (strcmp(Input, "quit") == 0) {
		    printf("Shutting down server...\n");
		    
		    // Notify all clients that server is shutting down
    	            broadcast_message("SERVER", "*** Server is shutting down ***", NULL);
    	            
    	            #ifndef _WIN32
        		usleep(100000);  // 100ms
    	            #endif
    	            
    	            raise(SIGINT);
    	            
		    break;
		    	    
		}
		
		if (strcmp(Input, "/users") == 0) {
		    char users_list[256];
		    get_online_users(users_list, sizeof(users_list));
		    printf("%s\n", users_list);
		} else {
		    // Broadcast server message to all clients
		    printf("[SERVER]: Broadcasting message to all clients\n");
		    broadcast_message("SERVER", Input, NULL);
		}
        	
		printf("[SERVER]: ");
		fflush(stdout);
	    }
	}
Error:

    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        // printf("[DEBUG] Send complete event\n");
        free(Event->SEND_COMPLETE.ClientContext);
        // printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        //printf("[strm][%p] Data received\n", Stream);
        //
    // Data was received from the peer on the stream.
    //
	    {
		for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
		    if (Event->RECEIVE.Buffers[i].Length >= sizeof(ChatMessageHeader)) {
		        ChatMessageHeader header;
		        deserialize_header(Event->RECEIVE.Buffers[i].Buffer, &header);
		        
		        // Check if this is a valid PDU
		        if (header.version == PROTOCOL_VERSION) {
		            // Handle PDU based on type
		            if (header.msg_type == MSG_TYPE_ACK && header.length == UCID_LENGTH) {
		                // LOGIN_SUCCESS - extract UCID
		                memcpy(GlobalClientUCID, 
		                       Event->RECEIVE.Buffers[i].Buffer + sizeof(ChatMessageHeader), 
		                       UCID_LENGTH);
		                printf("\n[CLIENT]: [Info] Login successful!\n");
		                print_ucid(GlobalClientUCID);
		                printf(">");
		                fflush(stdout);
		                continue;  // Skip to next buffer
		            } else if (header.msg_type == MSG_TYPE_TEXT && header.length == sizeof(TextPayload)) {
				// Handle TEXT PDU
				TextPayload text_payload;
				memcpy(&text_payload,
				       Event->RECEIVE.Buffers[i].Buffer + sizeof(ChatMessageHeader),
				       sizeof(TextPayload));
				
				// Display the message
				printf("\n%s\n>", text_payload.message);
				fflush(stdout);
				continue;
			    }
		            // Handle other PDU types later
		            continue;
		        }
		    }
		    char Message[MaxMessageLength];
		    uint32_t Length = Event->RECEIVE.Buffers[i].Length;
		    if (Length >= MaxMessageLength) {
		        Length = MaxMessageLength - 1;
		    }
		    memcpy(Message, Event->RECEIVE.Buffers[i].Buffer, Length);
		    Message[Length] = '\0';
		    
		    // Handle different message types
		    if (strcmp(Message, "LOGIN_SUCCESS") == 0) {
		        printf("\n[CLIENT]:[Info] Login successful!\n[CLIENT]: ");
		        fflush(stdout);
		    } else if (strncmp(Message, "LOGIN_FAILED", 12) == 0) {
		        printf("\n[Error] Login failed: %s\n", Message);
		        // TODO: Handle login failure (disconnect?)
		    } else if (strncmp(Message, "ERROR:", 6) == 0) {
		        printf("\n%s\n>", Message);
		        fflush(stdout);
		    } else {
		        // Regular chat message - just display it
		        printf("\n%s\n>", Message);
		        fflush(stdout);
		    }
		}
	    }
        break;
        // KAY
        // printf("[DEBUG] Receive event\n");
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[DEBUG] Peer send shutdown event\n");
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        //printf("[DEBUG] Shutdown complete event\n");
        //printf("[strm][%p] All done\n", Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->StreamClose(Stream);
        }
        // KAY
        GlobalClientStream = NULL;
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

/*void
ClientSend(
    _In_ HQUIC Connection
    )
{
    QUIC_STATUS Status;
    HQUIC Stream = NULL;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    printf("[conn] In client send...\n");
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", Stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(Stream);
        goto Error;
    }

    //
    // Allocates and builds the buffer to send over the stream.
    //
    SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}*/
// KAY
void
ClientCreateStream(
    _In_ HQUIC Connection
    )
{
    QUIC_STATUS Status;

    //
    // Create/allocate a new bidirectional stream.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, NULL, &GlobalClientStream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        return;
    }

    //
    // Start the bidirectional stream.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamStart(GlobalClientStream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(GlobalClientStream);
        GlobalClientStream = NULL;
        return;
    }
    
    printf("[CLIENT]: [Info] Stream created - waiting for AUTH");
    //fflush(stdout);
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        /*printf("[conn][%p] Connected\n", Connection);
        ClientSend(Connection);*/
    	GlobalClientConnection = Connection;
    	ClientCreateStream(Connection);
    	// Send login message after stream is created
    	if (GlobalClientStream != NULL) {
    		SendLoginPDU(GlobalClientStream, GlobalClientUsername, GlobalClientPassword);
        	/*char loginMsg[128];
        	snprintf(loginMsg, sizeof(loginMsg), "LOGIN:%s:%s", 
                 	GlobalClientUsername, GlobalClientPassword);
        	SendMessage(GlobalClientStream, loginMsg);*/
       	}
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("%s All done\n", GlobalClientUsername);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
            printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        }
        printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(
    BOOLEAN Unsecure,
    _In_opt_z_ const char* Cert
    )
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));

    //Update for cert file


    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (Unsecure) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
    if (Cert != NULL) {
        printf("[cfg ] Cert File: %s\n", Cert);
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
        CredConfig.CaCertificateFile = Cert;
    }
    
    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the client side of the protocol.
//
void
RunClient(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    const char* Cert;
    BOOLEAN unsecure_flag;

    // printf("DEBUG: Client Configuration: %d\n", GetFlag(argc, argv, "unsecure"));

    if ((Cert = GetValue(argc, argv, "cert_file")) != NULL) {
        printf("[cfg ] Cert File: %s\n", Cert);
    } else {
        printf("[cfg ] NO CERT File\n");
    }

    unsecure_flag = GetFlag(argc, argv, "unsecure");

    if  (unsecure_flag && Cert != NULL) {
        printf("[cfg ] Must specify -cert-flag or -unsecure, not both, exiting...\n");
        return;
    }

    if (!ClientLoadConfiguration(unsecure_flag, Cert)) {
        printf("ClientLoadConfiguration Unsecure Flag Early Exit!\n");
        return;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;
    HQUIC Connection = NULL;

    // KAY
    char Input[1024];
    char username[32];   
    char password[32];   
    
    //
    // Get username and password from user
    //
    printf("Username: ");
    fflush(stdout);
    if (fgets(username, sizeof(username), stdin) == NULL) {
        printf("Failed to read username\n");
        return;
    }
    username[strcspn(username, "\n")] = '\0';  // Remove newline

    printf("Password: ");
    fflush(stdout);
    if (fgets(password, sizeof(password), stdin) == NULL) {
        printf("Failed to read password\n");
       return;
    }
    password[strcspn(password, "\n")] = '\0';  // Remove newline
	
    printf("Attempting to login as '%s'...\n", username);
    
    strncpy(GlobalClientUsername, username, sizeof(GlobalClientUsername) - 1);
    GlobalClientUsername[sizeof(GlobalClientUsername) - 1] = '\0';
    strncpy(GlobalClientPassword, password, sizeof(GlobalClientPassword) - 1);
    GlobalClientPassword[sizeof(GlobalClientPassword) - 1] = '\0';
    
    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if ((ResumptionTicketString = GetValue(argc, argv, "ticket")) != NULL) {
        //
        // If provided at the command line, set the resumption ticket that can
        // be used to resume a previous session.
        //
        uint8_t ResumptionTicket[10240];
        uint16_t TicketLength = (uint16_t)DecodeHexBuffer(ResumptionTicketString, sizeof(ResumptionTicket), ResumptionTicket);
        if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, TicketLength, ResumptionTicket))) {
            printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", Status);
            goto Error;
        }
    }

    //
    // Get the target / server name or IP from the command line.
    //
    const char* Target;
    if ((Target = GetValue(argc, argv, "target")) == NULL) {
        printf("Must specify '-target' argument!\n");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    // printf("[conn][%p] Connecting...\n", Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }
    
    // KAY
    //
    // Wait for connection and then handle user input
    //
    if (!QUIC_FAILED(Status)) {
           //printf("Connecting to server...\n");
           printf("[CLIENT]: [Info] Connected to server - State: INIT\n");
    
    while (1) {
        if (!QUIC_FAILED(Status)) {
	    // printf("[CLIENT] Connected to server - State: INIT\n");
	}
	          
        if (fgets(Input, sizeof(Input), stdin) != NULL) {
            // Remove newline
            // printf("[DEBUG] Got input: '%s'\n", Input);
            Input[strcspn(Input, "\n")] = '\0';
            
            // Skip empty inputs
            if (strlen(Input) == 0) {
                // printf("[DEBUG] Skipping empty input\n");
                continue;  // Skip to next iteration
            }
            // Close Client
            if (strcmp(Input, "quit") == 0) {
                printf("[CLIENT]: [Info] Disconnected from server - State: DISCON\n");
                if (GlobalClientStream != NULL) {
                    MsQuic->StreamShutdown(GlobalClientStream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
                }
                break;
            }
            
            // Send the message if we have a stream
            if (GlobalClientStream != NULL) {
    		//SendMessage(GlobalClientStream, Input);
    		static uint32_t client_msg_id = 1;
    		SendTextPDU(GlobalClientStream, client_msg_id++, 0, GlobalClientUCID, Input);
    		//printf("[CLIENT]: ");
    		//fflush(stdout);
	    }
            else {
            	printf("[DEBUG] fgets returned NULL!\n");
                printf("Not connected. Type 'quit' to exit.\n");
            }
        }
    }
    
    // Clean shutdown
    if (Connection != NULL) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

Error:

    if (QUIC_FAILED(Status) && Connection != NULL) {
        MsQuic->ConnectionClose(Connection);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{

    srand(time(NULL));
    		
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
    } else if (GetFlag(argc, argv, "client")) {
        RunClient(argc, argv);
    } else if (GetFlag(argc, argv, "server")) {
        RunServer(argc, argv);
    } else {
        PrintUsage();
    }

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}

