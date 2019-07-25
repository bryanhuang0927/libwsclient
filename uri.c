//
// Created by morrowind xie on 2019/6/4.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <uri.h>

#ifdef _MEMDBG_
#include <memdbg.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static uri_query_t **_uri_decode_query(char *str, int *size) {
    char *p = strtok(str, "&");
    uri_query_t **queries = NULL, **new_queries = NULL;
    *size = 0;
    while(p != NULL) {
        new_queries = (uri_query_t **)realloc(queries, (*size+1) * sizeof(uri_query_t *));
        if(new_queries == NULL) {
            break;
        } else {
            queries = new_queries;
            new_queries = NULL;
            queries[*size] = (uri_query_t *)malloc(sizeof(uri_query_t));
            char *pp = strchr(p, '=');
            if(pp != NULL) {
                *pp = 0;
            }
            queries[*size]->key = strdup(p);
            if(pp != NULL) {
                queries[*size]->value = strdup(pp+1);
            }
            (*size)++;
            p = strtok(NULL, "&");
        }
    }
    return queries;
}

uri_t *uri_decode(const char *str) {
    uri_t *uri = (uri_t *)malloc(sizeof(uri_t));
    memset(uri, 0, sizeof(uri_t));
    char *copy = strdup(str);
    char *sp = copy;
    char *ep = strstr(sp, "://");
    char *p;

    if(ep == NULL) {
        fprintf(stderr, "no scheme");
        free(copy);
        uri_free(uri);
        return NULL;
    }
    *ep = '\0';
    uri->scheme = strdup(sp);
    ep += 3;
    sp = ep;

    ep = strrchr(sp, '#');
    if(ep != NULL) {
        uri->fragment = strdup(ep+1);
        *ep = 0;
    }
    ep = strrchr(sp, '?');
    if(ep != NULL) {
        uri->queries = _uri_decode_query(ep+1, &uri->query_size);
        *ep = 0;
    }

    ep = strchr(sp, '/');
    if(ep != NULL) {
        uri->path = strdup(ep);
        *ep = 0;
    } else {
        uri->path = strdup("/");
    }

    ep = strchr(sp, '@');
    if(ep != NULL) {
        *ep = 0;
        p = strchr(sp, ':');
        if(p != NULL) {
            *p = 0;
            uri->authority.username = strdup(sp);
            p++;
            uri->authority.password = strdup(p);
        }
        sp = ep+1;
    }
    p = strchr(sp, ':');
    if(p == NULL) {
        uri->authority.host = strdup(sp);
    } else {
        *p = 0;
        uri->authority.host = strdup(sp);
        uri->authority.port = strdup(p+1);
    }

    free(copy);
    return uri;
}

static int _uri_length(const uri_t *uri) {
    size_t len = 0;
    len += strlen(uri->scheme);
    len += 3; // ://
    if(uri->authority.username != NULL) {
        len += strlen(uri->authority.username);
        len += 1; // :
        len += strlen(uri->authority.password);
        len += 1; // @
    }
    len += strlen(uri->authority.host);
    if(uri->authority.port != NULL) {
        len += 1; // :
        len += strlen(uri->authority.port);
    }
    if(uri->path != NULL) {
        len += strlen(uri->path);
    } else {
        len += 1; // /
    }
    for(int i=0; i<uri->query_size; i++) {
        len += 1; // ? or &
        len += strlen(uri->queries[i]->key);
        len += 1; // =
        len += strlen(uri->queries[i]->value);
    }
    if(uri->fragment != NULL) {
        len += 1; // #
        len += strlen(uri->fragment);
    }
    return len;
}

const char *uri_encode(const uri_t *uri) {
    size_t len = _uri_length(uri);
    char *str = (char *)malloc(len+1);
    memset(str, 0, len+1);

    strcat(str, uri->scheme);
    strcat(str, "://");
    if(uri->authority.username != NULL) {
        strcat(str, uri->authority.username);
        strcat(str, ":");
        strcat(str, uri->authority.password);
        strcat(str, "@");
    }
    strcat(str, uri->authority.host);
    if(uri->authority.port != NULL) {
        strcat(str, ":");
        strcat(str, uri->authority.port);
    }
    if(uri->path != NULL) {
        strcat(str, uri->path);
    } else {
        strcat(str, "/");
    }
    for(int i=0; i<uri->query_size; i++) {
        if(i==0) {
            strcat(str, "?");
        } else {
            strcat(str, "&");
        }
        strcat(str, uri->queries[i]->key);
        strcat(str, "=");
        strcat(str, uri->queries[i]->value);
    }
    if(uri->fragment != NULL) {
        strcat(str, "#");
        strcat(str, uri->fragment);
    }
    return str;
}

void uri_free(uri_t *uri) {
    if(uri != NULL) {
        if(uri->scheme != NULL) {
            free(uri->scheme);
        }
        if(uri->authority.username != NULL) {
            free(uri->authority.username);
        }
        if(uri->authority.password != NULL) {
            free(uri->authority.password);
        }
        if(uri->authority.host != NULL) {
            free(uri->authority.host);
        }
        if(uri->authority.port != NULL) {
            free(uri->authority.port);
        }
        if(uri->path != NULL) {
            free(uri->path);
        }
        for(int i=0; i<uri->query_size; i++) {
            uri_query_t *query = uri->queries[i];
            if(query != NULL) {
                if(query->key != NULL) {
                    free(query->key);
                }
                if(query->value != NULL) {
                    free(query->value);
                }
            }
        }
        if(uri->queries != NULL) {
            free(uri->queries);
        }
        if(uri->fragment != NULL) {
            free(uri->fragment);
        }
        free(uri);
    }
}

#ifdef __cplusplus
}
#endif
