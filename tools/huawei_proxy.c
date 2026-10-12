#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT 8888
#define TARGET_IP   "192.168.8.1"
#define TARGET_PORT 80
#define BUFFER_SIZE 65536

typedef struct {
    int client_fd;
} client_ctx_t;

/* Replace all occurrences of needle with replacement in buffer */
static int replace_string(char *buf, int len, int max_size, const char *needle, const char *replacement) {
    char *pos = strcasestr(buf, needle);
    if (!pos) return len;

    size_t nlen = strlen(needle);
    size_t rlen = strlen(replacement);
    int diff = (int)rlen - (int)nlen;

    if (len + diff >= max_size) return len;

    memmove(pos + rlen, pos + nlen, len - (pos - buf) - nlen);
    memcpy(pos, replacement, rlen);
    return len + diff;
}

static void *handle_client(void *arg) {
    client_ctx_t *ctx = (client_ctx_t *)arg;
    int cfd = ctx->client_fd;
    free(ctx);

    char *req = malloc(BUFFER_SIZE);
    char *resp = malloc(BUFFER_SIZE);
    if (!req || !resp) {
        free(req);
        free(resp);
        close(cfd);
        return NULL;
    }

    /* Set 10-second timeout on client socket */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t n = read(cfd, req, BUFFER_SIZE - 512);
    if (n <= 0) {
        free(req);
        free(resp);
        close(cfd);
        return NULL;
    }
    req[n] = '\0';
    int req_len = (int)n;

    /* 1. Rewrite Host header to 192.168.8.1 */
    char *host_hdr = strcasestr(req, "Host:");
    if (host_hdr) {
        char *eol = strstr(host_hdr, "\r\n");
        if (eol) {
            char new_host[64];
            snprintf(new_host, sizeof(new_host), "Host: %s", TARGET_IP);
            int old_host_len = (int)(eol - host_hdr);
            memmove(host_hdr + strlen(new_host), eol, req_len - (eol - req));
            memcpy(host_hdr, new_host, strlen(new_host));
            req_len += (int)strlen(new_host) - old_host_len;
            req[req_len] = '\0';
        }
    }

    /* 2. Enforce Connection: close to avoid keep-alive desync */
    char *conn_hdr = strcasestr(req, "Connection:");
    if (conn_hdr) {
        char *eol = strstr(conn_hdr, "\r\n");
        if (eol) {
            const char *new_conn = "Connection: close";
            int old_conn_len = (int)(eol - conn_hdr);
            memmove(conn_hdr + strlen(new_conn), eol, req_len - (eol - req));
            memcpy(conn_hdr, new_conn, strlen(new_conn));
            req_len += (int)strlen(new_conn) - old_conn_len;
            req[req_len] = '\0';
        }
    }

    /* Connect to Huawei Router on eth1 */
    int tfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tfd < 0) {
        free(req);
        free(resp);
        close(cfd);
        return NULL;
    }

    setsockopt(tfd, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, "eth1", 4);
    setsockopt(tfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in taddr;
    memset(&taddr, 0, sizeof(taddr));
    taddr.sin_family = AF_INET;
    taddr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &taddr.sin_addr);

    if (connect(tfd, (struct sockaddr *)&taddr, sizeof(taddr)) < 0) {
        close(tfd);
        free(req);
        free(resp);
        close(cfd);
        return NULL;
    }

    /* Send modified request to Huawei */
    if (write(tfd, req, req_len) <= 0) {
        close(tfd);
        free(req);
        free(resp);
        close(cfd);
        return NULL;
    }

    /* Read response from Huawei and stream to client */
    ssize_t r = read(tfd, resp, BUFFER_SIZE - 512);
    if (r > 0) {
        resp[r] = '\0';
        int resp_len = (int)r;

        /* If response has Location: http://192.168.8.1..., rewrite it! */
        char *loc = strcasestr(resp, "Location: http://192.168.8.1");
        if (loc) {
            resp_len = replace_string(resp, resp_len, BUFFER_SIZE,
                                      "Location: http://192.168.8.1",
                                      "Location: http://10.121.15.35:8888");
        }

        /* Forward first chunk */
        if (write(cfd, resp, resp_len) > 0) {
            /* Stream remaining chunks if any */
            while (1) {
                ssize_t more = read(tfd, resp, BUFFER_SIZE);
                if (more <= 0) break;
                if (write(cfd, resp, more) <= 0) break;
            }
        }
    }

    close(tfd);
    close(cfd);
    free(req);
    free(resp);
    return NULL;
}

int main(int argc, char **argv) {
    int port = LISTEN_PORT;
    if (argc > 1) port = atoi(argv[1]);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    if (bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sfd);
        return 1;
    }

    if (listen(sfd, 128) < 0) {
        perror("listen");
        close(sfd);
        return 1;
    }

    printf("[Huawei Reverse Proxy V2] Listening on 0.0.0.0:%d -> %s:%d\n", port, TARGET_IP, TARGET_PORT);
    fflush(stdout);

    while (1) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        int cfd = accept(sfd, (struct sockaddr *)&caddr, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            usleep(50000);
            continue;
        }

        client_ctx_t *ctx = malloc(sizeof(client_ctx_t));
        if (!ctx) {
            close(cfd);
            continue;
        }
        ctx->client_fd = cfd;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&attr, 512 * 1024);
        if (pthread_create(&tid, &attr, handle_client, ctx) != 0) {
            free(ctx);
            close(cfd);
        }
        pthread_attr_destroy(&attr);
    }

    close(sfd);
    return 0;
}
