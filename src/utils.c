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
