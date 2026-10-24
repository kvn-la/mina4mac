// WININET over libcurl, the six calls the game imports. Its one user is the backend request at 0x85da50:
// InternetOpenA → InternetConnectA(takapuoli.noitagame.com, 443) → HttpOpenRequestA("GET", "callback/",
// INTERNET_FLAG_SECURE | RELOAD | NO_CACHE_WRITE | ...) → HttpSendRequestA → InternetReadFile in 1 KB reads.
// The reply carries the daily run and daily practice seeds and the latest version; without it the daily run
// says "connection failed". The request is synchronous, like WinINet's; the timeouts bound the stall.
// MINA4MAC_OFFLINE=1 restores the old behaviour: InternetOpenA fails (ERROR_INTERNET_NAME_NOT_RESOLVED).
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "host.h"
#include "proc.h"

enum {
    ERROR_INVALID_HANDLE = 6,
    ERROR_INTERNET_TIMEOUT = 12002,
    ERROR_INTERNET_INTERNAL_ERROR = 12004,
    ERROR_INTERNET_NAME_NOT_RESOLVED = 12007,
    ERROR_INTERNET_CANNOT_CONNECT = 12029,
    ERROR_INTERNET_SECURITY_CHANNEL_ERROR = 12157,
    INTERNET_FLAG_SECURE = 0x00800000,
    INTERNET_DEFAULT_HTTPS_PORT = 443,
};

typedef enum { H_FREE, H_SESSION, H_CONNECT, H_REQUEST } Kind;
typedef struct {
    Kind kind;
    char *agent;              // session
    char *server;             // connect
    uint16_t port;            // connect
    char *verb, *object, *version;  // request
    uint32_t flags, parent;   // request: its connect handle; connect: its session
    char *body;               // request: the response body after HttpSendRequestA
    size_t len, pos;
} Handle;

enum { MAX_HANDLES = 64, HANDLE_BASE = 0x7e1a0000 };  // guest handles are HANDLE_BASE + 4 * slot (never 0)
static Handle H[MAX_HANDLES];
static pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;

static void set_error(CPU *c, uint32_t err) { wr32(c->fs_base + TEB_LAST_ERROR, err); }
static char *sdup(const char *s) { return strdup(s ? s : ""); }
static void curl_init(void) { curl_global_init(CURL_GLOBAL_DEFAULT); }

static uint32_t h_new(Kind k) {  // under LOCK
    for (int i = 0; i < MAX_HANDLES; i++)
        if (H[i].kind == H_FREE) {
            memset(&H[i], 0, sizeof H[i]);
            H[i].kind = k;
            return HANDLE_BASE + 4 * i;
        }
    return 0;
}
static Handle *h_get(uint32_t h, Kind k) {  // under LOCK
    uint32_t i = (h - HANDLE_BASE) / 4;
    if (h < HANDLE_BASE || (h - HANDLE_BASE) % 4 || i >= MAX_HANDLES || H[i].kind == H_FREE) return NULL;
    return H[i].kind == k ? &H[i] : NULL;
}

static int offline(void) {
    const char *e = getenv("MINA4MAC_OFFLINE");
    return e && *e && strcmp(e, "0");
}

// InternetOpenA(agent, access, proxy, bypass, flags)
HOST_STDCALL(wininet, InternetOpenA, 20) {
    if (offline()) { set_error(c, ERROR_INTERNET_NAME_NOT_RESOLVED); return ret_i32(c, 0); }
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, curl_init);
    pthread_mutex_lock(&LOCK);
    uint32_t h = h_new(H_SESSION);
    if (h) H[(h - HANDLE_BASE) / 4].agent = sdup(ARG_STR(0));
    pthread_mutex_unlock(&LOCK);
    if (!h) set_error(c, ERROR_INTERNET_INTERNAL_ERROR);
    ret_i32(c, h);
}

// InternetConnectA(session, server, port, user, password, service, flags, context)
HOST_STDCALL(wininet, InternetConnectA, 32) {
    const char *server = ARG_STR(1);
    pthread_mutex_lock(&LOCK);
    uint32_t h = h_get(ARG(0), H_SESSION) && server && *server ? h_new(H_CONNECT) : 0;
    if (h) {
        Handle *x = &H[(h - HANDLE_BASE) / 4];
        x->server = sdup(server);
        x->port = (uint16_t)ARG(2);
        x->parent = ARG(0);
    }
    pthread_mutex_unlock(&LOCK);
    if (!h) set_error(c, ERROR_INVALID_HANDLE);
    ret_i32(c, h);
}

// HttpOpenRequestA(connect, verb, object, version, referrer, accept types, flags, context)
HOST_STDCALL(wininet, HttpOpenRequestA, 32) {
    pthread_mutex_lock(&LOCK);
    uint32_t h = h_get(ARG(0), H_CONNECT) ? h_new(H_REQUEST) : 0;
    if (h) {
        Handle *x = &H[(h - HANDLE_BASE) / 4];
        const char *verb = ARG_STR(1);
        x->verb = sdup(verb && *verb ? verb : "GET");
        x->object = sdup(ARG_STR(2));
        x->version = sdup(ARG_STR(3));
        x->flags = ARG(6);
        x->parent = ARG(0);
    }
    pthread_mutex_unlock(&LOCK);
    if (!h) set_error(c, ERROR_INVALID_HANDLE);
    ret_i32(c, h);
}

typedef struct { char *p; size_t n; } Buf;
static size_t on_data(char *p, size_t sz, size_t n, void *u) {
    Buf *b = u;
    size_t k = sz * n;
    char *q = realloc(b->p, b->n + k + 1);
    if (!q) return 0;
    memcpy(q + b->n, p, k);
    b->p = q;
    b->n += k;
    b->p[b->n] = 0;
    return k;
}

// HttpSendRequestA(request, headers, headers length, optional, optional length). Like WinINet, an HTTP error
// status still succeeds (the body is whatever the server sent); only transport failures fail.
HOST_STDCALL(wininet, HttpSendRequestA, 20) {
    char url[2048], agent[256], verb[16], version[16];
    pthread_mutex_lock(&LOCK);
    Handle *r = h_get(ARG(0), H_REQUEST), *cn = r ? h_get(r->parent, H_CONNECT) : NULL;
    Handle *s = cn ? h_get(cn->parent, H_SESSION) : NULL;
    if (!r || !cn) {
        pthread_mutex_unlock(&LOCK);
        set_error(c, ERROR_INVALID_HANDLE);
        return ret_i32(c, 0);
    }
    int secure = (r->flags & INTERNET_FLAG_SECURE) || cn->port == INTERNET_DEFAULT_HTTPS_PORT;
    uint16_t port = cn->port ? cn->port : secure ? 443 : 80;
    const char *obj = r->object;
    snprintf(url, sizeof url, "%s://%s:%u%s%s", secure ? "https" : "http", cn->server, port, *obj == '/' ? "" : "/", obj);
    snprintf(agent, sizeof agent, "%s", s && s->agent && *s->agent ? s->agent : "mina4mac");
    snprintf(verb, sizeof verb, "%s", r->verb);
    snprintf(version, sizeof version, "%s", r->version);
    pthread_mutex_unlock(&LOCK);

    char *headers = NULL, *body = NULL;
    if (ARG(1)) {
        uint32_t hl = ARG(2);
        headers = hl == 0xffffffffu ? sdup(ARG_STR(1)) : strndup(ARG_STR(1), hl);
    }
    size_t body_len = ARG(4);
    if (ARG(3) && body_len) { body = malloc(body_len); memcpy(body, ARG_PTR(3), body_len); }

    CURL *k = curl_easy_init();
    Buf out = {0};
    struct curl_slist *hdrs = NULL;
    char *save = NULL;
    for (char *line = headers ? strtok_r(headers, "\r\n", &save) : NULL; line; line = strtok_r(NULL, "\r\n", &save))
        if (*line) hdrs = curl_slist_append(hdrs, line);
    curl_easy_setopt(k, CURLOPT_URL, url);
    curl_easy_setopt(k, CURLOPT_USERAGENT, agent);
    curl_easy_setopt(k, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(k, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(k, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(k, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(k, CURLOPT_NOSIGNAL, 1L);  // timeouts without SIGALRM (the game has many threads)
    curl_easy_setopt(k, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(k, CURLOPT_TIMEOUT, 10L);
    if (!strcasecmp(version, "HTTP/1.0")) curl_easy_setopt(k, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_0);
    if (body) {
        curl_easy_setopt(k, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(k, CURLOPT_POSTFIELDSIZE, (long)body_len);
    }
    if (strcasecmp(verb, "GET") && !(body && !strcasecmp(verb, "POST"))) curl_easy_setopt(k, CURLOPT_CUSTOMREQUEST, verb);
    CURLcode rc = curl_easy_perform(k);
    long status = 0;
    curl_easy_getinfo(k, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(k);
    free(headers);
    free(body);

    if (rc != CURLE_OK) {
        fprintf(stderr, "wininet: %s %s failed: %s\n", verb, url, curl_easy_strerror(rc));
        free(out.p);
        uint32_t err = rc == CURLE_COULDNT_RESOLVE_HOST ? ERROR_INTERNET_NAME_NOT_RESOLVED
                     : rc == CURLE_OPERATION_TIMEDOUT   ? ERROR_INTERNET_TIMEOUT
                     : rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_PEER_FAILED_VERIFICATION ? ERROR_INTERNET_SECURITY_CHANNEL_ERROR
                                                        : ERROR_INTERNET_CANNOT_CONNECT;
        set_error(c, err);
        return ret_i32(c, 0);
    }
    fprintf(stderr, "wininet: %s %s -> %ld, %zu bytes\n", verb, url, status, out.n);
    pthread_mutex_lock(&LOCK);
    if ((r = h_get(ARG(0), H_REQUEST))) {  // still open
        free(r->body);
        r->body = out.p;
        r->len = out.n;
        r->pos = 0;
        out.p = NULL;
    }
    pthread_mutex_unlock(&LOCK);
    free(out.p);
    if (!r) { set_error(c, ERROR_INVALID_HANDLE); return ret_i32(c, 0); }
    ret_i32(c, 1);
}

// InternetReadFile(request, buffer, size, &read): *read 0 with TRUE is the end of the body.
HOST_STDCALL(wininet, InternetReadFile, 16) {
    uint32_t buf = ARG(1), size = ARG(2), outp = ARG(3);
    pthread_mutex_lock(&LOCK);
    Handle *r = h_get(ARG(0), H_REQUEST);
    size_t n = 0;
    if (r) {
        n = r->len - r->pos < size ? r->len - r->pos : size;
        if (n) memcpy(host_ptr(buf), r->body + r->pos, n);
        r->pos += n;
    }
    pthread_mutex_unlock(&LOCK);
    if (outp) wr32(outp, (uint32_t)n);
    if (!r) set_error(c, ERROR_INVALID_HANDLE);
    ret_i32(c, r != NULL);
}

HOST_STDCALL(wininet, InternetCloseHandle, 4) {
    uint32_t h = ARG(0);
    pthread_mutex_lock(&LOCK);
    Handle *x = NULL;
    for (Kind k = H_SESSION; k <= H_REQUEST && !x; k++) x = h_get(h, k);
    if (x) {
        free(x->agent); free(x->server); free(x->verb); free(x->object); free(x->version); free(x->body);
        memset(x, 0, sizeof *x);  // H_FREE
    }
    pthread_mutex_unlock(&LOCK);
    if (!x) set_error(c, ERROR_INVALID_HANDLE);
    ret_i32(c, x != NULL);
}
