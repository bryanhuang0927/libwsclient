#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <base64.h>
#include <sha1.h>
#include <uri.h>
#include <wsclient.h>

#ifdef _MEMDBG_
#include <memdbg.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TAG "wsclient"
#if defined __ANDROID__
#include <android/log.h>
#define printf(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define fprintf(fd, ...) __android_log_print((fd==stdout ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR), TAG, __VA_ARGS__)
#elif defined __YODA__
#include <log/rlog.h>
#define printf(...) KLOGD(TAG, __VA_ARGS__)
#define fprintf(fd, ...) (fd==stdout ? KLOGD(TAG, __VA_ARGS__) : KLOGE(TAG, __VA_ARGS__))
#endif

#define FRAME_CHUNK_LENGTH 1024
#define HELPER_RECV_BUF_SIZE 1024

#define CLIENT_IS_SSL (1 << 0)
#define CLIENT_CONNECTING (1 << 1)
#define CLIENT_SHOULD_CLOSE (1 << 2)
#define CLIENT_SENT_CLOSE_FRAME (1 << 3)

#define REQUEST_HAS_CONNECTION (1 << 0)
#define REQUEST_HAS_UPGRADE (1 << 1)
#define REQUEST_VALID_STATUS (1 << 2)
#define REQUEST_VALID_ACCEPT (1 << 3)

#define WS_FRAGMENT_START (1 << 0)
#define WS_FRAGMENT_FIN (1 << 7)

#define WS_FLAGS_SSL_INIT (1 << 0)

typedef struct _wsclient_frame_t {
	uint32_t fin;
	uint32_t opcode;
	size_t mask_offset;
	size_t payload_offset;
	size_t rawdata_idx;
	size_t rawdata_sz;
	int payload_len;
	uint8_t *rawdata;
	struct _wsclient_frame_t *next_frame;
	struct _wsclient_frame_t *prev_frame;
	uint8_t mask[4];
} wsclient_frame_t;

typedef struct _wsclient {
    // public: 
	void (*run)(struct _wsclient *);
	void (*shutdown)(struct _wsclient *);
	int (*get_socket)(struct _wsclient *);
	int (*send)(struct _wsclient *, const uint8_t *, size_t);
	int (*send_text)(struct _wsclient *, const char *);

    // private:
	pthread_t handshake_thread;
	pthread_t run_thread;
	pthread_t beat_thead;

	pthread_mutex_t lock;
	pthread_mutex_t send_lock;
    pthread_mutex_t beat_lock;

	uri_t *uri;
	char *extra_header;
	int64_t beat_interval, beat_remain_ms, beat_start_ts;
    on_open_cb onopen;
    on_message_cb onmessage;
    on_error_cb onerror;
    on_close_cb onclose;

	int sockfd;
	unsigned int flags;
	wsclient_frame_t *current_frame;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
} wsclient;

static const char *WEBSOCKET_UUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

//Define errors
static const char *errors_message[] = {
    "Unknown error occured",
    "Error while getting address info",
    "Could connect to any address returned by getaddrinfo",
    "Error receiving values in client run main_thread",
    "Error during wsclient_close",
    "Error sending while handling control frame",
    "Received masked frame from server",
    "Got null pointer during message dispatch",
    "Attempted to send after close frame was sent",
    "Attempted to send during connect",
    "Attempted to send null payload",
    "Attempted to send too much values",
    "Error during send in wsclient_send",
    "Remote end closed connection during handshake",
    "Problem receiving values during handshake",
    "Remote web server responded with bad HTTP status during handshake",
    "Remote web server did not respond with upgrade header during handshake",
    "Remote web server did not respond with connection header during handshake",
    "Remote web server did not specify the appropriate Sec-WebSocket-Accept header during handshake",
    "WS_HELPER_ALREADY_BOUND_ERR",
    "WS_HELPER_CREATE_SOCK_ERR",
    "WS_HELPER_BIND_ERR",
    "WS_HELPER_LISTEN_ERR",
    "Error during wsclient_ping",
    "Error during wsclient_pong",
    NULL
};

static void wsclient_run(wsclient *c);
static void wsclient_shutdown(wsclient *c);
static int wsclient_get_socket(wsclient *c);
static int wsclient_send(wsclient *c, const uint8_t *data, size_t len);
static int wsclient_send_text(wsclient *c, const char *text);

static void *wsclient_handshake_thread(wsclient *c);
static void *wsclient_run_thread(wsclient *c);
static inline void wsclient_in_data(wsclient *c, uint8_t in);
static wsclient_error_t *wsclient_new_error(int errcode);
static ssize_t _wsclient_read(wsclient *c, void *buf, size_t length);
static ssize_t _wsclient_write(wsclient *c, const void *buf, size_t length);
static void wsclient_ping(wsclient *c);
static void wsclient_pong(wsclient *c);
static void wsclient_handle_control_frame(wsclient *c, wsclient_frame_t *ctl_frame);
static int wsclient_complete_frame(wsclient *c, wsclient_frame_t *frame);
static void wsclient_dispatch_message(wsclient *c, wsclient_frame_t *current);
static void wsclient_cleanup_frames(wsclient_frame_t *first);

static int wsclient_flags; // global flag for ssl

static int64_t get_current_time_millis(void) {
    int64_t ts;
    long ms;
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    ts = spec.tv_sec;
    ms = (long)round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        ts++;
        ms = 0;
    }
    return ts*1000 + ms;
}

wsclient_t *wsclient_new(wsclient_config_t *config) {
    if(config == NULL || config->uri == NULL) {
        fprintf(stderr, "Null server uri in wsclient_new.\n");
        exit(WS_EXIT_BAD_URI);
    }
    printf("wsclient_new(%s)\n", config->uri);

    wsclient *c = (wsclient *)malloc(sizeof(wsclient));
    if(c == NULL) {
        fprintf(stderr, "Unable to allocate memory in wsclient_new.\n");
        exit(WS_EXIT_MALLOC);
    }
    memset(c, 0, sizeof(wsclient));
    c->run = (void (*)(wsclient *))wsclient_run;
    c->shutdown = (void (*)(wsclient *))wsclient_shutdown;
    c->get_socket = (int (*)(wsclient *))wsclient_get_socket;
    c->send = (int (*)(wsclient *, const uint8_t *, size_t len))wsclient_send;
    c->send_text = (int (*)(wsclient *, const char *))wsclient_send_text;

    if(pthread_mutex_init(&c->lock, NULL) != 0) {
        fprintf(stderr, "Unable to init mutex in wsclient_new.\n");
        exit(WS_EXIT_PTHREAD_MUTEX_INIT);
    }
    if(pthread_mutex_init(&c->send_lock, NULL) != 0) {
        fprintf(stderr, "Unable to init send lock in wsclient_new.\n");
        exit(WS_EXIT_PTHREAD_MUTEX_INIT);
    }
    if(pthread_mutex_init(&c->beat_lock, NULL) != 0) {
        fprintf(stderr, "Unable to init beat lock in wsclient_new.\n");
        exit(WS_EXIT_PTHREAD_MUTEX_INIT);
    }
    c->uri = uri_decode(config->uri);
    if(c->uri == NULL) {
        fprintf(stderr, "Decode URI failed in wsclient_new.\n");
        exit(WS_EXIT_BAD_URI);
    }
    if(config->extra_header != NULL) {
        c->extra_header = strdup(config->extra_header);
    }
    c->beat_interval = config->heart_beat_interval;
    c->onopen = config->open_cb;
    c->onmessage = config->message_cb;
    c->onerror = config->error_cb;
    c->onclose = config->close_cb;

    c->flags |= CLIENT_CONNECTING;

    if(pthread_create(&c->handshake_thread, NULL, (void *(*)(void *))wsclient_handshake_thread, (void *)c)) {
        fprintf(stderr, "Unable to create handshake main_thread.\n");
        exit(WS_EXIT_PTHREAD_CREATE);
    }
    return (wsclient_t *)c;
}

static void wsclient_run(wsclient *c) {
    printf("wsclient_run()\n");
    if(c->flags & CLIENT_CONNECTING) {
        pthread_join(c->handshake_thread, NULL);
        pthread_mutex_lock(&c->lock);
        c->flags &= ~CLIENT_CONNECTING;
        pthread_mutex_unlock(&c->lock);
    }
    if(c->sockfd) {
        pthread_create(&c->run_thread, NULL, (void *(*)(void *))wsclient_run_thread, (void *)c);
    }
    if(c->run_thread) {
        pthread_join(c->run_thread, NULL);
    }
}

static int wsclient_get_socket(wsclient *c) {
    return c->sockfd;
}

static void *wsclient_beat_thread(wsclient *c) {
    printf("wsclient_beat_thread()\n");
    pthread_mutex_lock(&c->beat_lock);
    c->beat_start_ts = get_current_time_millis();
    c->beat_remain_ms = c->beat_interval;
    pthread_mutex_unlock(&c->beat_lock);
    while(true) {
        if (c->beat_remain_ms > 1000) {
            usleep(1000*1000);
        } else if (c->beat_remain_ms > 0) {
            usleep(c->beat_remain_ms * 1000);
        }
        pthread_mutex_lock(&c->beat_lock);
        c->beat_remain_ms = c->beat_interval + c->beat_start_ts - get_current_time_millis();
        //printf("beat countdown: %"PRId64"\n", c->beat_remain_ms);
        if(c->beat_interval <= 0) {
            pthread_mutex_unlock(&c->beat_lock);
            break;
        } else if(c->beat_remain_ms <= 0) {
            c->beat_remain_ms = c->beat_interval;
            c->beat_start_ts = get_current_time_millis();
            pthread_mutex_unlock(&c->beat_lock);
            wsclient_ping(c);
        } else {
            pthread_mutex_unlock(&c->beat_lock);
        }
    }
    fprintf(stderr, "wsclient beat thread exited.\n");
    return NULL;
}

static void wsclient_beat_start(wsclient *c) {
    printf("wsclient_beat_start()\n");
    int ret = pthread_create(&c->beat_thead, NULL, (void *(*)(void *))wsclient_beat_thread, (void *)c);
    if (ret != 0) {
        fprintf(stderr, "Unable to create heart beat thread!\n");
        exit(WS_EXIT_PTHREAD_CREATE);
    }
}

static void wsclient_beat_reset(wsclient *c) {
    printf("wsclient_beat_reset()\n");
    pthread_mutex_unlock(&c->beat_lock);
    c->beat_remain_ms = c->beat_interval;
    c->beat_start_ts = get_current_time_millis();
    pthread_mutex_unlock(&c->beat_lock);
}

static void wsclient_beat_stop(wsclient *c) {
    printf("wsclient_beat_stop()\n");
    pthread_mutex_lock(&c->beat_lock);
    c->beat_interval = -1; // use this variable to check if quit beat thread
    pthread_mutex_unlock(&c->beat_lock);
}

static void *wsclient_run_thread(wsclient *c) {
    printf("wsclient_run_thread()\n");
    wsclient_error_t *err = NULL;
    int sockfd;
    uint8_t buf[FRAME_CHUNK_LENGTH];
    ssize_t n, i;
    
    if(c->beat_interval > 0) {
        wsclient_beat_start(c);
    }
    do {
        memset(buf, 0, sizeof(buf));
        n = _wsclient_read(c, (void *)buf, sizeof(buf)-1);
        printf("recv: %zd bytes\n", n);
        ssize_t printed_len = 0;
        char tmp[3*32+1] = {0};
        for(printed_len = 0; printed_len < n; printed_len+=32) {
            memset(tmp, 0, sizeof(tmp));
            for(ssize_t x=0; x<32 && printed_len+x<n; x++) {
                sprintf(&tmp[x*3], "%02x ", buf[printed_len+x]);
            }
            printf("hex: %s\n", tmp);
        }
        for(i = 0; i < n; i++) {
            wsclient_in_data(c, buf[i]);
        }
    } while(n > 0);

    if(n < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_RUN_THREAD_RECV_ERR);
            err->extra_code = n;
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
    }
    if(c->onclose) {
        c->onclose((wsclient_t *)c);
    }

    if(c->beat_interval > 0) {
        wsclient_beat_stop(c);
        pthread_join(c->beat_thead, NULL); // wait beat thread exit
    }

    if(c->flags & CLIENT_IS_SSL) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        SSL_CTX_free(c->ssl_ctx);
    }

    close(c->sockfd);
    uri_free(c->uri);
    if(c->extra_header) {
        free(c->extra_header);
    }
    wsclient_cleanup_frames(c->current_frame);
    pthread_mutex_destroy(&c->lock);
    pthread_mutex_destroy(&c->send_lock);
    pthread_mutex_destroy(&c->beat_lock);
    free(c);
    return NULL;
}

void wsclient_shutdown(wsclient *c) {
    printf("wsclient_shutdown()\n");
    wsclient_error_t *err = NULL;
    uint8_t data[6];
    ssize_t i = 0, n;
    int mask_int;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    mask_int = rand();
    memcpy(data+2, &mask_int, sizeof(mask_int));
    data[0] = 0x88;
    data[1] = 0x80;
    pthread_mutex_lock(&c->send_lock);
    do {
        n = _wsclient_write(c, (void *)data, sizeof(data));
        i += n;
    } while(i < 6 && n > 0);
    pthread_mutex_unlock(&c->send_lock);
    if(n < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_DO_CLOSE_SEND_ERR);
            err->extra_code = n;
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return;
    }
    pthread_mutex_lock(&c->lock);
    c->flags |= CLIENT_SENT_CLOSE_FRAME;
    pthread_mutex_unlock(&c->lock);
}

static void wsclient_ping(wsclient *c) {
    printf("wsclient_ping()\n");
    wsclient_error_t *err = NULL;
    uint8_t data[6];
    ssize_t i = 0, n;
    int mask_int;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    mask_int = rand();
    memcpy(data+2, &mask_int, sizeof(mask_int));
    data[0] = 0x89;
    data[1] = 0x80;
    pthread_mutex_lock(&c->send_lock);
    do {
        n = _wsclient_write(c, data, sizeof(data));
        i += n;
    } while(i < 6 && n > 0);
    pthread_mutex_unlock(&c->send_lock);
    if(n < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_DO_PING_SEND_ERR);
            err->extra_code = n;
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return;
    }
}

static void wsclient_pong(wsclient *c) {
    printf("wsclient_pong()\n");
    wsclient_error_t *err = NULL;
    uint8_t data[6];
    ssize_t i = 0, n;
    int mask_int;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    mask_int = rand();
    memcpy(data+2, &mask_int, sizeof(mask_int));
    data[0] = 0x8A;
    data[1] = 0x80;
    pthread_mutex_lock(&c->send_lock);
    do {
        n = _wsclient_write(c, data, sizeof(data));
        i += n;
    } while(i < 6 && n > 0);
    pthread_mutex_unlock(&c->send_lock);
    if(n < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_DO_PONG_SEND_ERR);
            err->extra_code = n;
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return;
    }
}

static void wsclient_handle_control_frame(wsclient *c, wsclient_frame_t *ctl_frame) {
    printf("wsclient_handle_control_frame(opcode=%02x)\n", ctl_frame->opcode);
    wsclient_error_t *err = NULL;
    wsclient_frame_t *ptr = NULL;
    ssize_t i, n = 0;
    uint8_t mask[4];
    int mask_int;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srand(tv.tv_sec * tv.tv_usec);
    mask_int = rand();
    memcpy(mask, &mask_int, sizeof(mask_int));
    pthread_mutex_lock(&c->lock);
    switch(ctl_frame->opcode) {
        case 0x08:
            //close frame
            if((c->flags & CLIENT_SENT_CLOSE_FRAME) == 0) {
                //server request close.  Send close frame as acknowledgement.
                for(i=0; i<ctl_frame->payload_len; i++) {
                    *(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (mask[i % 4] & 0xff); //mask payload
                }
                *(ctl_frame->rawdata + 1) |= 0x80; //turn mask bit on
                i = 0;
                pthread_mutex_lock(&c->send_lock);
                while(i < ctl_frame->payload_offset + ctl_frame->payload_len && n >= 0) {
                    n = _wsclient_write(c, ctl_frame->rawdata + i, ctl_frame->payload_offset + ctl_frame->payload_len - i);
                    i += n;
                }
                pthread_mutex_unlock(&c->send_lock);
                if(n < 0) {
                    if(c->onerror) {
                        err = wsclient_new_error(WS_HANDLE_CTL_FRAME_SEND_ERR);
                        err->extra_code = n;
                        c->onerror((wsclient_t *)c, err);
                        free(err);
                        err = NULL;
                    }
                }
            }
            c->flags |= CLIENT_SHOULD_CLOSE;
            break;
        case 0x09:
            // ping frame
            printf("received a ping frame, reply with a pong.");
            if((c->flags & CLIENT_SHOULD_CLOSE) == 0) {
                // Server sent ping.  Send pong frame as acknowledgement.
				for(i=0; i<ctl_frame->payload_len; i++) {
					*(ctl_frame->rawdata + ctl_frame->payload_offset + i) ^= (mask[i % 4] & 0xff); //mask payload
                }
				*(ctl_frame->rawdata + 1) |= 0x80; //turn mask bit on
				i = 0;
				// change opcode to 0xA (Pong Frame)
				*(ctl_frame->rawdata) = (*(ctl_frame->rawdata) & 0xf0) | 0x0A;
				pthread_mutex_lock(&c->send_lock);
				while(i < ctl_frame->payload_offset + ctl_frame->payload_len && n >= 0) {
					n = _wsclient_write(c, ctl_frame->rawdata + i, ctl_frame->payload_offset + ctl_frame->payload_len - i);
					i += n;
				}
				pthread_mutex_unlock(&c->send_lock);
				if(n < 0) {
					if(c->onerror) {
						err = wsclient_new_error(WS_HANDLE_CTL_FRAME_SEND_ERR);
						err->extra_code = n;
						c->onerror((wsclient_t *)c, err);
						free(err);
						err = NULL;
					}
				}
			}
            break;
        case 0x0A:
            // pong frame
            printf("received a pong frame, server still alive.\n");
            break;
        default:
            fprintf(stderr, "Unhandled control frame received.  Opcode: %u\n", ctl_frame->opcode);
            break;
    }

    ptr = ctl_frame->prev_frame; //This very well may be a NULL pointer, but just in case we preserve it.
    free(ctl_frame->rawdata);
    memset(ctl_frame, 0, sizeof(wsclient_frame_t));
    ctl_frame->prev_frame = ptr;
    ctl_frame->rawdata = (uint8_t *)malloc(FRAME_CHUNK_LENGTH);
    memset(ctl_frame->rawdata, 0, FRAME_CHUNK_LENGTH);
    pthread_mutex_unlock(&c->lock);
}

static inline void wsclient_in_data(wsclient *c, uint8_t in) {
    wsclient_frame_t *current = NULL, *new = NULL;
    unsigned char payload_len_short;
    pthread_mutex_lock(&c->lock);
    if(c->current_frame == NULL) {
        c->current_frame = (wsclient_frame_t *)malloc(sizeof(wsclient_frame_t));
        memset(c->current_frame, 0, sizeof(wsclient_frame_t));
        c->current_frame->payload_len = -1;
        c->current_frame->rawdata_sz = FRAME_CHUNK_LENGTH;
        c->current_frame->rawdata = (uint8_t *)malloc(c->current_frame->rawdata_sz);
        memset(c->current_frame->rawdata, 0, c->current_frame->rawdata_sz);
    }
    current = c->current_frame;
    if(current->rawdata_idx >= current->rawdata_sz) {
        current->rawdata_sz += FRAME_CHUNK_LENGTH;
        current->rawdata = (uint8_t *)realloc(current->rawdata, current->rawdata_sz);
        memset(current->rawdata + current->rawdata_idx, 0, current->rawdata_sz - current->rawdata_idx);
    }
    *(current->rawdata + current->rawdata_idx++) = in;
    pthread_mutex_unlock(&c->lock);
    int is_completed = wsclient_complete_frame(c, current);
    if(is_completed == 1) {
        if(current->fin == 1) {
            //is control frame
            if((current->opcode & 0x08) == 0x08) {
                wsclient_handle_control_frame(c, current);
            } else {
                wsclient_dispatch_message(c, current);
                c->current_frame = NULL;
            }
        } else {
            new = (wsclient_frame_t *)malloc(sizeof(wsclient_frame_t));
            memset(new, 0, sizeof(wsclient_frame_t));
            new->payload_len = -1;
            new->rawdata = (uint8_t *)malloc(FRAME_CHUNK_LENGTH);
            memset(new->rawdata, 0, FRAME_CHUNK_LENGTH);
            new->prev_frame = current;
            current->next_frame = new;
            c->current_frame = new;
        }
    }
}

static void wsclient_dispatch_message(wsclient *c, wsclient_frame_t *current) {
    printf("wsclient_dispatch_message()\n");
    size_t message_payload_len, message_offset;
    int message_opcode, i;
    uint8_t *message_payload;
    wsclient_frame_t *first = NULL;
    wsclient_message_t *msg = NULL;
    wsclient_error_t *err = NULL;
    if(current == NULL) {
        if(c->onerror) {
            err = wsclient_new_error(WS_DISPATCH_MESSAGE_NULL_PTR_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return;
    }
    message_offset = 0;
    message_payload_len = current->payload_len;
    for(;current->prev_frame != NULL;current = current->prev_frame) {
        message_payload_len += current->payload_len;
    }
    first = current;
    message_opcode = current->opcode;
    message_payload = (uint8_t *)malloc(message_payload_len + 1);
    memset(message_payload, 0, message_payload_len + 1);
    for(;current != NULL; current = current->next_frame) {
        memcpy(message_payload + message_offset, current->rawdata + current->payload_offset, current->payload_len);
        message_offset += current->payload_len;
    }

    wsclient_cleanup_frames(first);
    msg = (wsclient_message_t *)malloc(sizeof(wsclient_message_t));
    memset(msg, 0, sizeof(wsclient_message_t));
    msg->opcode = message_opcode;
    msg->payload_len = message_offset;
    msg->payload = message_payload;
    if(c->onmessage != NULL) {
        c->onmessage((wsclient_t *)c, msg);
    } else {
        fprintf(stderr, "No onmessage call back registered with wsclient.\n");
    }
    free(msg->payload);
    free(msg);
}

static void wsclient_cleanup_frames(wsclient_frame_t *first) {
    printf("wsclient_cleanup_frames()\n");
    if(first == NULL) {
        return;
    }
    wsclient_frame_t *next = NULL;
    while(first->prev_frame != NULL) {
        first = first->prev_frame;
    }
    while(first != NULL) {
        next = first->next_frame;
        if(first->rawdata != NULL) {
            free(first->rawdata);
        }
        free(first);
        first = next;
    }
}

static int wsclient_complete_frame(wsclient *c, wsclient_frame_t *frame) {
    wsclient_error_t *err = NULL;
    int payload_len_short, i;
    unsigned long long payload_len = 0;
    if(frame->rawdata_idx < 2) {
        return 0;
    }
    frame->fin = (*(frame->rawdata) & 0x80) == 0x80 ? 1 : 0;
    frame->opcode = *(frame->rawdata) & 0x0f;
    frame->payload_offset = 2;
    if((*(frame->rawdata+1) & 0x80) != 0x0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_COMPLETE_FRAME_MASKED_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        pthread_mutex_lock(&c->lock);
        c->flags |= CLIENT_SHOULD_CLOSE;
        pthread_mutex_unlock(&c->lock);
        return 0;
    }
    payload_len_short = *(frame->rawdata+1) & 0x7f;
    switch(payload_len_short) {
    case 126:
        if(frame->rawdata_idx < 4) {
            return 0;
        }
        for(i = 0; i < 2; i++) {
            memcpy((char *)&payload_len+i, frame->rawdata+3-i, 1);
        }
        frame->payload_offset += 2;
        frame->payload_len = payload_len;
        break;
    case 127:
        if(frame->rawdata_idx < 10) {
            return 0;
        }
        for(i = 0; i < 8; i++) {
            memcpy((char *)&payload_len+i, frame->rawdata+9-i, 1);
        }
        frame->payload_offset += 8;
        frame->payload_len = payload_len;
        break;
    default:
        frame->payload_len = payload_len_short;
        break;

    }
    if(frame->rawdata_idx < frame->payload_offset + frame->payload_len) {
        return 0;
    }
    return 1;
}

static int wsclient_open_connection(const char *host, const char *port) {
    printf("wsclient_open_connection(%s:%s)\n", host, port);
    struct addrinfo hints, *servinfo, *p;
    int rv, sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    fprintf(stdout, "host=%s, port=%s\n", host, port);
    if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        return WS_OPEN_CONNECTION_ADDRINFO_ERR;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if(p == NULL) {
        return WS_OPEN_CONNECTION_ADDRINFO_EXHAUSTED_ERR;
    }
    return sockfd;
}

static void show_certs(SSL *ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        char line[256];
        printf("cert info:\n");
        X509_NAME_oneline(X509_get_subject_name(cert), line, sizeof(line)-1);
        printf("  cert: %s\n", line);
        X509_NAME_oneline(X509_get_issuer_name(cert), line, sizeof(line)-1);
        printf("  from: %s\n", line);
        X509_free(cert);
    } else {
        fprintf(stderr, "No cert info!\n");
    }
}

static void *wsclient_handshake_thread(wsclient *c) {
    printf("wsclient_handshake_thread()\n");
    wsclient_error_t *err = NULL;
    SHA1Context shactx;
    char pre_encode[256];
    char sha1bytes[20];
    char expected_base64[512];
    char websocket_key[256];
    unsigned char key_nonce[16];
    char recv_buf[1024];
    char *p = NULL, *rcv = NULL, *tok = NULL;
    int z, sockfd, n, flags = 0;

    if(c->uri->scheme == NULL) {
        fprintf(stderr, "Malformed or missing scheme for URI.\n");
        exit(WS_EXIT_BAD_SCHEME);
    }
    if(strcmp(c->uri->scheme, "ws") != 0 && strcmp(c->uri->scheme, "wss") != 0) {
        fprintf(stderr, "Invalid scheme for URI: %s\n", c->uri->scheme);
        exit(WS_EXIT_BAD_SCHEME);
    }
    pthread_mutex_lock(&c->lock);
    if(strcmp(c->uri->scheme, "ws") == 0) {
        if(c->uri->authority.port == NULL) {
            c->uri->authority.port = strdup("80");
        }
    } else { // wss
        if(c->uri->authority.port == NULL) {
            c->uri->authority.port = strdup("443");
        }
        c->flags |= CLIENT_IS_SSL;
    }
    pthread_mutex_unlock(&c->lock);

    sockfd = wsclient_open_connection(c->uri->authority.host, c->uri->authority.port);
    if(sockfd < 0) {
        if(c->onerror) {
            err = wsclient_new_error(sockfd);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }

    if(c->flags & CLIENT_IS_SSL) {
        if((wsclient_flags & WS_FLAGS_SSL_INIT) == 0) {
            SSL_library_init();
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            wsclient_flags |= WS_FLAGS_SSL_INIT;
        }
        c->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if(c->ssl_ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        c->ssl = SSL_new(c->ssl_ctx);
        SSL_set_fd(c->ssl, sockfd);
        if(SSL_connect(c->ssl) == -1) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("Connected with %s encryption.\n", SSL_get_cipher(c->ssl));
            show_certs(c->ssl);
        }
    }

    pthread_mutex_lock(&c->lock);
    c->sockfd = sockfd;
    pthread_mutex_unlock(&c->lock);

    //perform handshake
    //generate nonce
    srand(time(NULL));
    for(z=0; z<sizeof(key_nonce); z++) {
        key_nonce[z] = (unsigned char)(rand() & 0xff);
    }
    base64_encode(key_nonce, sizeof(key_nonce), websocket_key, sizeof(websocket_key));

    size_t request_host_len = strlen(c->uri->authority.host);
    if(strcmp(c->uri->authority.port, "80") != 0) {
        request_host_len += (1 + strlen(c->uri->authority.port));
    }
    char *request_host = (char *)malloc(request_host_len+1);
    if(request_host == NULL) {
        fprintf(stderr, "No memory available (request_host).\n");
        exit(WS_EXIT_MALLOC);
    }
    memset(request_host, 0, request_host_len+1);
    strcpy(request_host, c->uri->authority.host);
    if(strcmp(c->uri->authority.port, "80") != 0) {
        strcat(request_host, ":");
        strcat(request_host, c->uri->authority.port);
    }

    const char *request_header_format = "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13";
    size_t request_header_len = strlen(request_header_format);
    request_header_len += strlen(c->uri->path);
    request_header_len += strlen(request_host);
    request_header_len += strlen(websocket_key);
    if(c->extra_header != NULL) {
        request_header_len += (strlen(c->extra_header) + 2);
    }
    request_header_len += strlen("\r\n\r\n");
    char *request_header = (char *)malloc(request_header_len+1);
    if(request_header == NULL) {
        fprintf(stderr, "No memory available (request_header).\n");
        exit(WS_EXIT_MALLOC);
    }
    memset(request_header, 0, request_header_len+1);
    snprintf(request_header, request_header_len, request_header_format, c->uri->path, request_host, websocket_key);
    free(request_host);
    if(c->extra_header != NULL) {
        strcat(request_header, "\r\n");
        strcat(request_header, c->extra_header);
    }
    strcat(request_header, "\r\n\r\n");
    printf("websocket requests:\n%s\n", request_header);
    n = _wsclient_write(c, request_header, strlen(request_header));
    free(request_header);

    z = 0;
    memset(recv_buf, 0, sizeof(recv_buf));
    //TODO: actually handle values after \r\n\r\n in case server
    // sends post-handshake values that gets coalesced in this recv
    do {
        n = _wsclient_read(c, recv_buf + z, sizeof(recv_buf) -1 - z);
        z += n;
    } while((z < 4 || strstr(recv_buf, "\r\n\r\n") == NULL) && n > 0);
    printf("recevied handshake result = \n%s\n", recv_buf);
    if(n == 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_HANDSHAKE_REMOTE_CLOSED_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }
    if(n < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_HANDSHAKE_RECV_ERR);
            err->extra_code = n;
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }
    //parse recv_buf for response headers and assure Accept matches expected values
    rcv = (char *)malloc(strlen(recv_buf)+1);
    if(!rcv) {
        fprintf(stderr, "Unable to allocate memory in wsclient_new.\n");
        exit(WS_EXIT_MALLOC);
    }
    memset(rcv, 0, strlen(recv_buf)+1);
    strncpy(rcv, recv_buf, strlen(recv_buf));
    memset(pre_encode, 0, sizeof(pre_encode));
    snprintf(pre_encode, sizeof(pre_encode)-1, "%s%s", websocket_key, WEBSOCKET_UUID);
    SHA1Reset(&shactx);
    SHA1Input(&shactx, (unsigned char *)pre_encode, strlen(pre_encode));
    SHA1Result(&shactx);
    memset(pre_encode, 0, sizeof(pre_encode));
    snprintf(pre_encode, sizeof(pre_encode)-1, "%08x%08x%08x%08x%08x", shactx.Message_Digest[0], shactx.Message_Digest[1], shactx.Message_Digest[2], shactx.Message_Digest[3], shactx.Message_Digest[4]);
    for(z = 0; z < (strlen(pre_encode)/2);z++)
        sscanf(pre_encode+(z*2), "%02hhx", sha1bytes+z);
    memset(expected_base64, 0, sizeof(expected_base64));
    base64_encode((unsigned char *)sha1bytes, 20, expected_base64, 512);
    for(tok = strtok(rcv, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")) {
        if(strncasecmp(tok, "HTTP/1.1 101", 12) == 0 && strncasecmp(tok, "HTTP/1.0 101", 12) == 0) {
            flags |= REQUEST_VALID_STATUS;
        } else {
            p = strchr(tok, ' ');
            *p = '\0';
            if(strcasecmp(tok, "Upgrade:") == 0) {
                if(strcasecmp(p+1, "websocket") == 0) {
                    flags |= REQUEST_HAS_UPGRADE;
                }
            }
            if(strcasecmp(tok, "Connection:") == 0) {
                if(strcasecmp(p+1, "upgrade") == 0) {
                    flags |= REQUEST_HAS_CONNECTION;
                }
            }
            if(strcasecmp(tok, "Sec-WebSocket-Accept:") == 0) {
                if(strcmp(p+1, expected_base64) == 0) {
                    flags |= REQUEST_VALID_ACCEPT;
                }
            }
        }
    }
    free(rcv);
    if(!(flags & REQUEST_HAS_UPGRADE)) {
        if(c->onerror) {
            err = wsclient_new_error(WS_HANDSHAKE_NO_UPGRADE_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }
    if(!(flags & REQUEST_HAS_CONNECTION)) {
        if(c->onerror) {
            err = wsclient_new_error(WS_HANDSHAKE_NO_CONNECTION_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }
    if(!(flags & REQUEST_VALID_ACCEPT)) {
        if(c->onerror) {
            err = wsclient_new_error(WS_HANDSHAKE_BAD_ACCEPT_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return NULL;
    }

    pthread_mutex_lock(&c->lock);
    c->flags &= ~CLIENT_CONNECTING;
    pthread_mutex_unlock(&c->lock);
    if(c->onopen != NULL) {
        c->onopen((wsclient_t *)c);
    }
    printf("handshake OK (handshake thread exit)\n");
    return NULL;
}

static wsclient_error_t *wsclient_new_error(int errcode) {
    wsclient_error_t *err = (wsclient_error_t *)malloc(sizeof(wsclient_error_t));
    if(!err) {
        //one of the few places we will fail and exit
        fprintf(stderr, "Unable to allocate memory in wsclient_new_error.\n");
        exit(errcode);
    }
    memset(err, 0, sizeof(wsclient_error_t));
    err->code = errcode;
    if(errcode < WS_HANDSHAKE_BAD_ACCEPT_ERR) {
        errcode = 0;
    }
    err->str = errors_message[-errcode];
    return err;
}

static int wsclient_send_fragment(wsclient *c, char *text, int len, int flags) {
    printf("wsclient_send_fragment(len:%d)\n", len);
    wsclient_error_t *err = NULL;
    struct timeval tv;
    unsigned char mask[4];
    unsigned int mask_int;
    unsigned long long payload_len;
    //unsigned char finNopcode;
    unsigned int payload_len_small;
    unsigned int payload_offset = 6;
    unsigned int len_size;
    //unsigned long long be_payload_len;
    unsigned int sent = 0;
    int i;
    unsigned int frame_size;
    char *data = NULL;

    if(c->flags & CLIENT_SENT_CLOSE_FRAME) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_AFTER_CLOSE_FRAME_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }
    if(c->flags & CLIENT_CONNECTING) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DURING_CONNECT_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }

    if(text == NULL) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_NULL_DATA_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec * tv.tv_sec);
    mask_int = rand();
    memcpy(mask, &mask_int, 4);
    payload_len = len;
    if(payload_len <= 125) {
        frame_size = 6 + payload_len;
        payload_len_small = payload_len;

    } else if(payload_len <= 0xffff) {
        frame_size = 8 + payload_len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if(payload_len <= 0xffffffffffffffffLL) {
        frame_size = 14 + payload_len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DATA_TOO_LARGE_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }
    data = (char *)malloc(frame_size);

    memset(data, 0, frame_size);
    *data = flags & 0xff;
    *(data+1) = payload_len_small | 0x80; //payload length with mask bit on
    if(payload_len_small == 126) {
        payload_len &= 0xffff;
        len_size = 2;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    if(payload_len_small == 127) {
        payload_len &= 0xffffffffffffffffLL;
        len_size = 8;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    for(i=0;i<4;i++)
        *(data+(payload_offset-4)+i) = mask[i] & 0xff;

    memcpy(data+payload_offset, text, len);
    for(i=0;i<len;i++)
        *(data+payload_offset+i) ^= mask[i % 4] & 0xff;
    sent = 0;
    i = 1;

    //we don't need the send lock here.  It *should* have already been acquired before sending fragmented message
    //and will be released after last fragment sent.
    while(sent < frame_size && i > 0) {
        i = _wsclient_write(c, data+sent, frame_size - sent);
        sent += i;
    }


    if(i < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_SEND_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
    }

    free(data);
    return sent;
}

int wsclient_send(wsclient *c, const uint8_t *bindata, size_t bindata_len)  {
    printf("wsclient_send_binary(len:%zu, flags:%08x)\n", bindata_len, c->flags);
    wsclient_error_t *err = NULL;
    struct timeval tv;
    unsigned char mask[4];
    unsigned int mask_int;
    unsigned long long payload_len;
    unsigned char finNopcode;
    unsigned int payload_len_small;
    unsigned int payload_offset = 6;
    unsigned int len_size;
    unsigned long long be_payload_len;
    unsigned int sent = 0;
    int i;
    unsigned int frame_size;
    char *data;

    if(c->flags & CLIENT_SENT_CLOSE_FRAME) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_AFTER_CLOSE_FRAME_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }
    if(c->flags & CLIENT_CONNECTING) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DURING_CONNECT_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }
    if(bindata == NULL || bindata_len == 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_NULL_DATA_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec * tv.tv_sec);
    mask_int = rand();
    memcpy(mask, &mask_int, 4);
    payload_len = bindata_len;
    finNopcode = 0x82; //FIN and binary opcode.
    if(payload_len <= 125) {
        frame_size = 6 + payload_len;
        payload_len_small = payload_len;

    } else if(payload_len <= 0xffff) {
        frame_size = 8 + payload_len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if(payload_len <= 0xffffffffffffffffLL) {
        frame_size = 14 + payload_len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DATA_TOO_LARGE_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
        }
        return 0;
    }
    data = (char *)malloc(frame_size);
    if(data == NULL) {
        fprintf(stderr, "Malloc failed when wsclient_send_binary @line_%d\n", __LINE__);
        return -1;
    }
    memset(data, 0, frame_size);
    *data = finNopcode;
    *(data+1) = payload_len_small | 0x80; //payload length with mask bit on
    if(payload_len_small == 126) {
        payload_len &= 0xffff;
        len_size = 2;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    if(payload_len_small == 127) {
        payload_len &= 0xffffffffffffffffLL;
        len_size = 8;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    for(i=0;i<4;i++)
        *(data+(payload_offset-4)+i) = mask[i];

    memcpy(data+payload_offset, bindata, bindata_len);
    for(i=0;i<bindata_len;i++)
        *(data+payload_offset+i) ^= mask[i % 4] & 0xff;

    sent = 0;
    i = 0;
    pthread_mutex_lock(&c->send_lock);
    while(sent < frame_size && i >= 0) {
        i = _wsclient_write(c, data+sent, frame_size - sent);
        sent += i;
    }
    pthread_mutex_unlock(&c->send_lock);
    if(i < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_SEND_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            free(data);
            return 0;
        }
    }

    free(data);

    wsclient_beat_reset(c);
    printf("successful send %zu bytes data.\n", bindata_len);
    return sent;
}

int wsclient_send_text(wsclient *c, const char *text) {
    size_t data_len = (text != NULL) ? strlen(text) : 0;
    printf("wsclient_send_txtdata(len:%zu)\n", data_len);
    wsclient_error_t *err = NULL;
    struct timeval tv;
    unsigned char mask[4];
    unsigned int mask_int;
    unsigned long long payload_len;
    unsigned char finNopcode;
    unsigned int payload_len_small;
    unsigned int payload_offset = 6;
    unsigned int len_size;
    unsigned long long be_payload_len;
    unsigned int sent = 0;
    int i, sockfd;
    unsigned int frame_size;
    char *data;

    sockfd = c->sockfd;

    if(c->flags & CLIENT_SENT_CLOSE_FRAME) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_AFTER_CLOSE_FRAME_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return 0;
    }
    if(c->flags & CLIENT_CONNECTING) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DURING_CONNECT_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return 0;
    }
    if(text == NULL) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_NULL_DATA_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return 0;
    }

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec * tv.tv_sec);
    mask_int = rand();
    memcpy(mask, &mask_int, 4);
    payload_len = strlen(text);
    finNopcode = 0x81; //FIN and text opcode.
    if(payload_len <= 125) {
        frame_size = 6 + payload_len;
        payload_len_small = payload_len;

    } else if(payload_len <= 0xffff) {
        frame_size = 8 + payload_len;
        payload_len_small = 126;
        payload_offset += 2;
    } else if(payload_len <= 0xffffffffffffffffLL) {
        frame_size = 14 + payload_len;
        payload_len_small = 127;
        payload_offset += 8;
    } else {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_DATA_TOO_LARGE_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
        return -1;
    }
    data = (char *)malloc(frame_size);
    memset(data, 0, frame_size);
    *data = finNopcode;
    *(data+1) = payload_len_small | 0x80; //payload length with mask bit on
    if(payload_len_small == 126) {
        payload_len &= 0xffff;
        len_size = 2;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    if(payload_len_small == 127) {
        payload_len &= 0xffffffffffffffffLL;
        len_size = 8;
        for(i = 0; i < len_size; i++) {
            *(data+2+i) = *((char *)&payload_len+(len_size-i-1));
        }
    }
    for(i=0;i<4;i++)
        *(data+(payload_offset-4)+i) = mask[i];

    memcpy(data+payload_offset, text, strlen(text));
    for(i=0;i<strlen(text);i++)
        *(data+payload_offset+i) ^= mask[i % 4] & 0xff;
    sent = 0;
    i = 0;

    pthread_mutex_lock(&c->send_lock);
    while(sent < frame_size && i >= 0) {
        i = _wsclient_write(c, data+sent, frame_size - sent);
        sent += i;
    }
    pthread_mutex_unlock(&c->send_lock);

    if(i < 0) {
        if(c->onerror) {
            err = wsclient_new_error(WS_SEND_SEND_ERR);
            c->onerror((wsclient_t *)c, err);
            free(err);
            err = NULL;
        }
    }

    free(data);

    wsclient_beat_reset(c);
    return sent;
}

ssize_t _wsclient_read(wsclient *c, void *buf, size_t length) {
    if(c->flags & CLIENT_IS_SSL) {
        return (ssize_t)SSL_read(c->ssl, buf, length);
    } else {
        return recv(c->sockfd, buf, length, 0);
    }
}

ssize_t _wsclient_write(wsclient *c, const void *buf, size_t length) {
    if(c->flags & CLIENT_IS_SSL) {
        return (ssize_t)SSL_write(c->ssl, buf, length);
    } else {
        return send(c->sockfd, buf, length, 0);
    }
}

#ifdef __cplusplus
}
#endif
