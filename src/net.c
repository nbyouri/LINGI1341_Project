#include "common.h"

/**
 *
 * Network handling functions
 *
 */

const char *
real_address(const char *address, struct sockaddr_in6 *rval)
{
    int error;
    const char *error_msg = NULL;
    struct addrinfo hints, *result, *resalloc;

    /* zero the structures to be safe */
    memset(&hints, 0, sizeof(hints));
    memset(rval, 0, sizeof(struct sockaddr_in6));

    /* initialise hints as ipv6 and udp */
    hints.ai_family = IP_VERSION;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    /* detect listening on all interfaces */
    if (memcmp(address, IP_ANY, BUFSIZ) == 0) {
        rval->sin6_family = IP_VERSION;
        rval->sin6_addr = in6addr_any;
        return error_msg;
    }


    /* get a linked list of possible sockaddr objects */
    if ((error = getaddrinfo(address, NULL, &hints, &result)) != 0) {
        error_msg = gai_strerror(error);
    }

    resalloc = result;

    /* go through the linked list and find ipv6 addresses */
    while (result) {
        if (result->ai_family == IP_VERSION) {
            memcpy(rval,(struct sockaddr_in6 *)result->ai_addr, sizeof(*rval));
            rval->sin6_family = IP_VERSION;
            break;
        }

        result = result->ai_next;
    }

    /* free the linked list */
    freeaddrinfo(resalloc);

    return error_msg;
}

int
create_socket(struct sockaddr_in6 *source_addr, int src_port,
    struct sockaddr_in6 *dest_addr, int dst_port)
{

    int s = 0, b = 0, c = 0;
    int is_server = 1;

    /* create ipv6 udp socket */
    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s == -1) {
        ERROR("%s\n", strerror(errno));
        return s;
    }

    struct sockaddr_in6 addr;
    int port = -1;

    /* find out if we're a server or a client */
    if ((source_addr != NULL) && (src_port > 0)) {
        memcpy(&addr, source_addr, sizeof(addr));
        port = src_port;
    } else if ((dest_addr != NULL) && (dst_port > 0)) {
        is_server = 0;
        memcpy(&addr, dest_addr, sizeof(addr));
        port = dst_port;
    } else {
        return -1;
    }

    addr.sin6_port = htons(port);

    if (is_server) {
        /* bind if we're a server */
        b = bind(s, (struct sockaddr *)&addr, sizeof(addr));
        if (b == -1) {
            ERROR("%s\n", strerror(errno));
            return c;
        }
    } else {
        /* connect to the socket if we're a client */
        c = connect(s, (struct sockaddr *)&addr, sizeof(addr));
        if (c == -1) {
            ERROR("%s\n", strerror(errno));
            return c;
        }
    }

    return s;
}

/*
 * Wait for data received from a client to identify its source so we can
 * send data back to the client.
 */
int
wait_for_client(int sfd)
{
    char buf[1024];
    socklen_t socklen;
    struct sockaddr_storage addr;

    memset(&addr, 0, sizeof(addr));
    socklen = sizeof(addr);
    ssize_t bytes_received = recvfrom(sfd, buf, sizeof(buf), MSG_PEEK,
        (struct sockaddr *)&addr, &socklen);
    if (bytes_received == -1) {
        ERROR("recvfrom failed : %s\n", strerror(errno));
        return -1;
    } else {
        int c = connect(sfd, (struct sockaddr *)&addr, socklen);
        if (c == -1) {
            ERROR("connect failed : %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}
