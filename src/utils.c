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
    INFO("[-f <filename>] <address> <port>\n");
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
    struct stat fs;

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
    *buf = malloc(length);
    if (buf == NULL) {
	ERROR("Failed to allocate memory.\n");
	return 0;
    }
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
