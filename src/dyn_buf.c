#include "dyn_buf.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DYN_BUF_DEFAULT_CAPACITY 2048

static int dyn_buf_grow(dyn_buf_t *buf, size_t needed) {
    if (!buf) return -1;
    if (buf->len + needed + 1 <= buf->capacity) return 0;

    size_t new_cap = buf->capacity ? buf->capacity * 2 : DYN_BUF_DEFAULT_CAPACITY;
    while (new_cap < buf->len + needed + 1) {
        new_cap *= 2;
    }

    char *new_data = (char *)realloc(buf->data, new_cap);
    if (!new_data) return -1;

    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

void dyn_buf_init(dyn_buf_t *buf, size_t initial_capacity) {
    if (!buf) return;
    size_t cap = initial_capacity ? initial_capacity : DYN_BUF_DEFAULT_CAPACITY;
    buf->data = (char *)malloc(cap);
    if (buf->data) {
        buf->data[0] = '\0';
        buf->capacity = cap;
    } else {
        buf->capacity = 0;
    }
    buf->len = 0;
}

int dyn_buf_vprintf(dyn_buf_t *buf, const char *fmt, va_list args) {
    if (!buf || !fmt) return -1;

    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (needed < 0) return -1;

    if (dyn_buf_grow(buf, (size_t)needed) != 0) return -1;

    int written = vsnprintf(buf->data + buf->len, buf->capacity - buf->len, fmt, args);
    if (written > 0) {
        buf->len += (size_t)written;
    }
    return written;
}

int dyn_buf_printf(dyn_buf_t *buf, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int res = dyn_buf_vprintf(buf, fmt, args);
    va_end(args);
    return res;
}

int dyn_buf_append(dyn_buf_t *buf, const char *str) {
    if (!str) return 0;
    return dyn_buf_append_len(buf, str, strlen(str));
}

int dyn_buf_append_len(dyn_buf_t *buf, const char *str, size_t len) {
    if (!buf || !str || len == 0) return 0;
    if (dyn_buf_grow(buf, len) != 0) return -1;

    memcpy(buf->data + buf->len, str, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return (int)len;
}

void dyn_buf_free(dyn_buf_t *buf) {
    if (!buf) return;
    if (buf->data) {
        free(buf->data);
        buf->data = NULL;
    }
    buf->len = 0;
    buf->capacity = 0;
}

const char *dyn_buf_cstr(const dyn_buf_t *buf) {
    if (!buf || !buf->data) return "";
    return buf->data;
}
