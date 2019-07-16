#ifndef WSCLIENT_H_
#define WSCLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

// Define exit reason
#define WS_EXIT_MALLOC -1
#define WS_EXIT_PTHREAD_MUTEX_INIT -2
#define WS_EXIT_PTHREAD_CREATE -3
#define WS_EXIT_BAD_SCHEME -4
#define WS_EXIT_BAD_URI -5

// Define error code
#define WS_OPEN_CONNECTION_ADDRINFO_ERR -1
#define WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR -2
#define WS_RUN_THREAD_RECV_ERR -3
#define WS_DO_CLOSE_SEND_ERR -4
#define WS_HANDLE_CTL_FRAME_SEND_ERR -5
#define WS_COMPLETE_FRAME_MASKED_ERR -6
#define WS_DISPATCH_MESSAGE_NULL_PTR_ERR -7
#define WS_SEND_AFTER_CLOSE_FRAME_ERR -8
#define WS_SEND_DURING_CONNECT_ERR -9
#define WS_SEND_NULL_DATA_ERR -10
#define WS_SEND_DATA_TOO_LARGE_ERR -11
#define WS_SEND_SEND_ERR -12
#define WS_HANDSHAKE_REMOTE_CLOSED_ERR -13
#define WS_HANDSHAKE_RECV_ERR -14
#define WS_HANDSHAKE_BAD_STATUS_ERR -15
#define WS_HANDSHAKE_NO_UPGRADE_ERR -16
#define WS_HANDSHAKE_NO_CONNECTION_ERR -17
#define WS_HANDSHAKE_BAD_ACCEPT_ERR -18
#define WS_HELPER_ALREADY_BOUND_ERR -19
#define WS_HELPER_CREATE_SOCK_ERR -20
#define WS_HELPER_BIND_ERR -21
#define WS_HELPER_LISTEN_ERR -22
#define WS_DO_PING_SEND_ERR -23
#define WS_DO_PONG_SEND_ERR -24

typedef struct _wsclient_t wsclient_t;

typedef struct {
	unsigned int opcode;
	size_t payload_len;
	uint8_t *payload;
} wsclient_message_t;

typedef struct {
	int code;
	int extra_code;
	const char *str;
} wsclient_error_t;

typedef int (*on_open_cb)(wsclient_t *client);
typedef int (*on_message_cb)(wsclient_t *client, wsclient_message_t *msg);
typedef int (*on_error_cb)(wsclient_t *client, wsclient_error_t *err);
typedef int (*on_close_cb)(wsclient_t *client);

typedef struct {
	const char *uri; // server uri
	const char *extra_header; // extra header of http request in handshake or set null if not needed
	int heart_beat_interval; // send heart beat by client every this millisecs or set 0 if only send ping by server
	on_open_cb open_cb;
	on_message_cb message_cb;
	on_error_cb error_cb;
	on_close_cb close_cb;
} wsclient_config_t;

struct _wsclient_t {
	void (*run)(wsclient_t *client);
	void (*shutdown)(wsclient_t *client);
	int (*get_socket)(wsclient_t *client);
	int (*send)(wsclient_t *client, const uint8_t *data, size_t len);
	int (*send_text)(wsclient_t *client, const char *text);
};

/**
 * Create a new websocket client with specified configuration.
 * @params config - The configuration.
 * @return The websocket client instance.
 */
wsclient_t *wsclient_new(wsclient_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* WSCLIENT_H_ */
