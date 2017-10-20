#include "common.h"

/**
 *
 * General utilities
 *
 */

/*
 * Program help.
 *
 */
void
help()
{
    printf("%s: [-f <filename>] <address> <port>\n", PROGRAM_NAME);
}

/*
 * Parse integer from string.
 *
 */
int
parse_port(const char *string)
{
    long val = -1;
    if ((val = strtol(string, NULL, 10)) == 0) {
        ERROR("Invalid port.\n");
        return -1;
    }
    if (val < 1024) {
        ERROR("This port is reserved for the system.\n");
        return -1;
    }
    if (val > 65535) {
        ERROR("Port value too big.\n");
        return -1;
    }
    return (int)val;
}

/*
 * Find file by name.
 *
 */
int
file_exists(const char *path)
{
    struct stat fs = {0};

    return stat(path, &fs);
}

/*
 * Read file to buffer
 *
 */
FILE *
open_file(const char *path, int append)
{
    FILE *f;

    f = fopen(path, append ? "a+" : "r");
    if (f == NULL) {
	ERROR("Failed to open file %s\n", path);
    }
    return f;
}

/*
 * Load file to buffer
 *
 */
size_t
read_file(FILE *f, char **buf, size_t length)
{
    return fread(*buf, sizeof(char), length, f);
}

/*
 * Get file size
 *
 */
int
file_size(FILE *f)
{
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);
    return size;
}

/*
 * Write (append) to a file
 *
 */
int
write_file(FILE *f, const char *buf, size_t length)
{
    return fwrite(buf, sizeof(char), length, f);
}

/*
 * Set position in file
 *
 */
int
file_set_position(FILE *f, size_t pos)
{
    return fseek(f, pos, SEEK_SET);
}

/*
 * Read from stdin until EOF is reached and return amount of bytes read
 *
 */
size_t
read_stdin(char **buf)
{
    *buf = malloc(BUFSIZ);
    if (*buf == NULL) {
        ERROR("Failed to malloc *buf\n");
        return E_NOMEM;
    }
    memset(*buf, 0, BUFSIZ);
    size_t len = 0;
    while (!feof(stdin)) {
        char tmp[BUFSIZ];
        memset(tmp, 0, BUFSIZ);
        size_t read = fread(tmp, 1, BUFSIZ, stdin);
        *buf = realloc(*buf, len + read);
        if (*buf == NULL) {
            ERROR("Failed to realloc buffer for stdin\n");
            return E_NOMEM;
        }
        memcpy(*buf + len, tmp, read);
        len += read;
    }
    return len;
}

/*
 * Compare two timeval, return left > right
 *
 */
int
timeval_cmp(const struct timeval *left, const struct timeval *right)
{
	return left->tv_sec == right->tv_sec ?
		left->tv_usec > right->tv_usec :
		left->tv_sec > right->tv_sec;
}

/*
 *  Get difference between to timeval ( c = a - b )
 *
 */
void
timeval_diff(const struct timeval *a, const struct timeval *b, struct timeval *c)
{
	c->tv_sec = a->tv_sec - b->tv_sec;
	c->tv_usec = a->tv_usec - b->tv_usec;
	if (c->tv_usec < 0) {
		if (--c->tv_sec)
			c->tv_usec += 1000000;
	}
}


/*
 * Update a timeval to the current time
 *
 */
void
update_time(struct timeval *clock)
{
#ifdef __APPLE__
	if (gettimeofday(clock, NULL)) {
		ERROR("Cannot get internal clock\n");
		exit(EXIT_FAILURE);
	}
#else
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		ERROR("Cannot get internal clock\n");
		exit(EXIT_FAILURE);
	}
	clock->tv_sec = ts.tv_sec;
	clock->tv_usec = ts.tv_nsec/1000;
#endif

}

/*
 * Compare packets based on their timestamp values
 *
 */
int
pkt_cmp(const void *a, const void *b)
{
    uint32_t left = ((pkt_t *)a)->header.timestamp;
    uint32_t right = ((pkt_t *)b)->header.timestamp;

    struct timeval time_left = unpack_timestamp(left);
    struct timeval time_right = unpack_timestamp(right);

    return timeval_cmp(&time_left, &time_right);
}
/*
 * Compare packets based on their timestamp values
 *  return a seqnum > b seqnum;
 */
int
pkt_cmp_seqnum(const void *a, const void *b)
{
	uint8_t left = ((pkt_t *)a)->header.seqnum;
	uint8_t right = ((pkt_t *)b)->header.seqnum;
	return left > right;
}
/*
 * Compare packets based on their seqnum values
 * return a seqnum == b seqnum
 */

int
pkt_cmp_seqnum2(const void *a, const void *b)
{
	uint8_t left = ((pkt_t *)a)->header.seqnum;
	uint8_t right = ((pkt_t *)b)->header.seqnum;
	return left == right;
}


/*
 * Pack timeval structure into a timestamp
 * FIXME maybe don't use current time?
 */
uint32_t
pack_timestamp(struct timeval tv) {
    uint32_t ts = 0;
    /* Pack seconds on the first 8 bits */
    if (tv.tv_sec > 255) {
        return 0;
    }
    ts = tv.tv_sec << 24;
    ts |= tv.tv_usec;
    return ts;
}

/*
 * Unpack timestamp to a timeval structure
 *
 */
struct timeval
unpack_timestamp(uint32_t ts) {
    struct timeval tv;
    /* First 8 bits contain the seconds */
    tv.tv_sec = ts & 0xFF000000;
    /* The remaining bits contain the microseconds */
    tv.tv_usec = ts & 0xFFFFFF;
    return tv;
}

