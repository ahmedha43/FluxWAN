#ifndef FLUXWAN_DYN_BUF_H
#define FLUXWAN_DYN_BUF_H

#include <stddef.h>
#include <stdarg.h>

/**
 * Dynamic String Buffer for high-performance, safe HTTP and JSON responses.
 * Automatically grows capacity as needed to prevent truncation or buffer overflow.
 */
typedef struct {
    char *data;
    size_t len;
    size_t capacity;
} dyn_buf_t;

void dyn_buf_init(dyn_buf_t *buf, size_t initial_capacity);
int  dyn_buf_printf(dyn_buf_t *buf, const char *fmt, ...);
int  dyn_buf_vprintf(dyn_buf_t *buf, const char *fmt, va_list args);
int  dyn_buf_append(dyn_buf_t *buf, const char *str);
int  dyn_buf_append_len(dyn_buf_t *buf, const char *str, size_t len);
void dyn_buf_free(dyn_buf_t *buf);
const char *dyn_buf_cstr(const dyn_buf_t *buf);

#endif /* FLUXWAN_DYN_BUF_H */
