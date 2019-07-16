//
// Created by morrowind xie on 2019/6/4.
//

#ifndef _URI_H
#define _URI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *key;
    char *value;
} uri_query_t;

typedef struct {
    char *scheme;
    struct {
        char *username;
        char *password;
        char *host;
        char *port;
    } authority;
    char *path;
    int query_size;
    uri_query_t **queries;
    char *fragment;
} uri_t;


uri_t *uri_decode(const char *uri);

const char *uri_encode(const uri_t *uri);

void uri_free(uri_t *uri);


#ifdef __cplusplus
}
#endif

#endif //EVENTCLIENT_URI_H
