#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "fluxwan.h"
#include "net_discovery.h"
#include "dhcp_server.h"
#include "netlink_manager.h"

typedef struct web_server_ctx web_server_ctx_t;

/**
 * Initialize Embedded Web Server on specified bind IP and port
 */
web_server_ctx_t *web_server_init(fluxwan_config_t *config, netlink_ctx_t *nl, dhcp_server_ctx_t *dhcp);

/**
 * Destroy Web Server
 */
void web_server_close(web_server_ctx_t *ctx);

/**
 * Get Web Server listening socket file descriptor for epoll integration
 */
socket_t web_server_get_fd(const web_server_ctx_t *ctx);

/**
 * Handle new incoming HTTP client connection on listening socket
 */
socket_t web_server_accept_client(web_server_ctx_t *ctx);

/**
 * Process client HTTP request / SSE connection
 */
int web_server_process_client(web_server_ctx_t *ctx, socket_t client_fd);

#endif /* WEB_SERVER_H */
