#ifndef __COMMON_H
#define __COMMON_H


/**
 * Common header for sender and receiver
 *
 * Nicolas Sias
 *      &
 * Youri Mouton
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <zlib.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>

/*
 *
 * Utility Macros
 *
 */

#define _INFO(file, prefix, msg, ...)               \
    do {                                            \
        fprintf(file, prefix ": "msg"\n",	    \
	##__VA_ARGS__);                             \
    } while(0)

#define LOG(msg, ...)       _INFO(stderr, "[LOG]", msg, ##__VA_ARGS__)
#define ERROR(msg, ...)     _INFO(stderr, "[ERROR]", msg, ##__VA_ARGS__)
#define INFO(msg, ...)      _INFO(stdout, "", msg, ##__VA_ARGS__)

#define MAX_PAYLOAD_SIZE    512
#define MAX_PKT_SIZE        sizeof(pkt_t) + MAX_PAYLOAD_SIZE - sizeof(char *)
#define ACK_PKT_SIZE        sizeof(pkt_t)
#define MAX_WINDOW_SIZE     31
#define MAX_SEQNUM          256
#define IP_VERSION          AF_INET6
#define IP_LENGTH           INET6_ADDRSTRLEN
#define IP_ANY              "::"
#define MAX_TIMEOUT	    2
/*
 *
 * Data Types
 *
 */

/* packet */
typedef struct __attribute__((__packed__)) {
    struct {
        uint8_t  window  : 5;
        uint8_t  tr      : 1;
        uint8_t  type    : 2;
        uint8_t  seqnum;
        uint16_t length;
        uint32_t timestamp;
        uint32_t crc1;
    } header;
    char *payload;
    uint32_t crc2;
} pkt_t;

/* packet types */
typedef enum {
    PTYPE_DATA = 1,
    PTYPE_ACK  = 2,
    PTYPE_NACK = 3,
} ptypes_t;

/* packet status codes */
typedef enum {
    PKT_OK = 0,     /* packet success */
    E_TYPE,         /* type error */
    E_TR,           /* tr error */
    E_LENGTH,       /* length error  */
    E_CRC,          /* crc error */
    E_WINDOW,       /* window error */
    E_SEQNUM,       /* seqnum error */
    E_NOMEM,        /* out of memory error */
    E_NOHEADER,     /* packet has no header (too short) */
    E_UNCONSISTENT, /* incoherent packet */
} pkt_status_code;

/**
 *
 * Function Prototypes
 *
 */

/* utils.c function prototypes */
void                help(void);
int                 parse_port(const char *);
int                 file_exists(const char *);
FILE*               open_file(const char *, int);
size_t              read_file(FILE *, char **, size_t);
int                 write_file(FILE *, const char *, size_t);
int                 file_size(FILE *);
int                 file_set_position(FILE *, size_t);
size_t              read_stdin(char **);
int		    timeval_cmp(const struct timeval *left, const struct timeval *right);
void 	            timeval_diff(const struct timeval *a, const struct timeval *b, struct timeval *c);
void	            update_time(struct timeval *clock);
/* pkt.c function prototypes */
pkt_t*              pkt_new();
void                pkt_del(pkt_t *);

pkt_status_code     pkt_decode(const char *, const size_t, pkt_t *);
pkt_status_code     pkt_encode(const pkt_t *, char *, size_t *);

ptypes_t            pkt_get_type(const pkt_t *);
uint8_t             pkt_get_tr(const pkt_t *);
uint8_t             pkt_get_window(const pkt_t *);
uint8_t             pkt_get_seqnum(const pkt_t *);
uint16_t            pkt_get_length(const pkt_t *);
uint32_t            pkt_get_timestamp(const pkt_t *);
uint32_t            pkt_get_crc1(const pkt_t *);
uint32_t            pkt_get_crc2(const pkt_t *);
const char*         pkt_get_payload(const pkt_t *);

pkt_status_code     pkt_set_type(pkt_t *, const ptypes_t);
pkt_status_code     pkt_set_tr(pkt_t *, const uint8_t);
pkt_status_code     pkt_set_window(pkt_t *, const uint8_t);
pkt_status_code     pkt_set_seqnum(pkt_t *, const uint8_t);
pkt_status_code     pkt_set_length(pkt_t *, const uint16_t);
pkt_status_code     pkt_set_timestamp(pkt_t *, const uint32_t);
pkt_status_code     pkt_set_crc1(pkt_t *, const uint32_t);
pkt_status_code     pkt_set_crc2(pkt_t *, const uint32_t);
pkt_status_code     pkt_set_payload(pkt_t *, const char *, const uint16_t);

uint32_t            pkt_gen_crc1(const pkt_t *);
uint32_t            pkt_gen_crc2(const pkt_t *);
void                pkt_to_string(const pkt_t *);
size_t              nb_pkt_in_buffer(const ssize_t);

/* net.c function prototypes */
const char*         real_address(const char *, struct sockaddr_in6 *);
int                 create_socket(struct sockaddr_in6 *, int,
                    struct sockaddr_in6 *, int);
int                 wait_for_client(int);
int                 encode_address(const char *, struct sockaddr_in6 *);
int                 decode_address(const struct sockaddr_in6 *, char *, size_t);

#endif /* __COMMON_H */
