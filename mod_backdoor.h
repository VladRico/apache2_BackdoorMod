typedef struct sock_userdata_t sock_userdata_t;

typedef struct apr_socket_t {
    apr_pool_t *cntxt;
    int socketdes;
    int type;
    int protocol;
    apr_sockaddr_t *local_addr;
    apr_sockaddr_t *remote_addr;
    apr_interval_time_t timeout;
    int local_port_unknown;
    int local_interface_unknown;
    int remote_addr_unknown;
    apr_int32_t netmask;
    apr_int32_t inherit;
    sock_userdata_t *userdata;
} apr_socket_t;
