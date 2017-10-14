/**
 * Receiver program.
 *
 * Nicolas Sias
 *      &
 * Youri Mouton
 *
 * For LINGI1341, October 2017, UCL.
 *
 */
#include "common.h"

typedef struct {
    pkt_t   *pkt;
    int     sent;
    int     ack;
} window_entry;

static window_entry **
init_window(size_t nelem)
{
    window_entry **w;
    w = malloc(nelem * sizeof(window_entry));
    if (w == NULL) {
        return NULL;
    }

    size_t i = 0;
    for (; i < nelem; w[++i] = NULL);

    return w;
}

static void
free_window(window_entry **w, size_t nelem)
{
    size_t i = 0;
    for (; i < nelem; i++) {
        free(w[i]);
        w[i] = NULL;
    }
    free(w);
    w = NULL;
}

/*
 * Returns the entry we need to start retransmission from
 * if none found, return the size of the window_entry
 */
static size_t
window_need_acknowledged(window_entry **w, size_t nelem)
{
    size_t i = 0;
    for (; i < nelem; i++) {
        if (w[i]->ack == 0) {
            return i;
        }
    }
    return nelem;
}

/*
 * Read the file from offset and during length bytes onto buf
 */
static int
get_payload(char **buf, FILE *f, size_t offset, size_t *length)
{
    *buf = realloc(*buf, *length);
    if (*buf == NULL) {
        return -1;
    }
    memset(*buf, '\0', *length);

    file_set_position(f, offset);
    size_t readf = read_file(f, buf, *length);
    if (readf <= 0) {
        ERROR("Failed to read file\n");
        return -1;
    }
    if (readf < *length) {
        *length = readf;
    }

    return 0;
}

/*
 * Create send buffer containing everything to send for the current window
 * and the status.
 */
static int
make_window(window_entry **w,
    size_t seqnum,
    size_t *expected_seqnum,
    size_t window,
    size_t pkt_to_send,
    FILE   *file,
    size_t *pos_in_file,
    size_t *payload_left_to_send)
{
    char    *payload_data = NULL;
    size_t  payload_len = MAX_PAYLOAD_SIZE;
    size_t  i = 0;

    for (; i < pkt_to_send; i++) {
        w[i] = calloc(1, sizeof(window_entry));
        if (w[i] == NULL) {
            return -1;
        }
        w[i]->pkt = pkt_new();

        pkt_set_type(w[i]->pkt, PTYPE_DATA);
        pkt_set_window(w[i]->pkt, window);
        pkt_set_seqnum(w[i]->pkt, seqnum);
        pkt_set_timestamp(w[i]->pkt, 0);

        /* read file to get payload */
        if (payload_len > *payload_left_to_send) {
            payload_len = *payload_left_to_send;
        }

        if (payload_len == 0) {
            payload_data = NULL;
        } else {
            get_payload(&payload_data, file, *pos_in_file, &payload_len);
            *pos_in_file += payload_len;
            *payload_left_to_send -= payload_len;
        }

        pkt_set_payload(w[i]->pkt, payload_data, payload_len);

        w[i]->sent = 0;
        w[i]->ack = 0;
    }

    *expected_seqnum += pkt_to_send;
    if (*expected_seqnum >= MAX_SEQNUM) {
        *expected_seqnum = *expected_seqnum - MAX_SEQNUM;
    }

    return 0;
}

/*
 * Loop through window entries and send them
 *
 */
static int
send_window(int socket, window_entry **w, size_t offset, size_t window)
{
    size_t  i = 0;
    size_t  temp_buflen = MAX_PKT_SIZE;
    char    *temp_buf = malloc(temp_buflen);
    int     sent = 0;
    if (temp_buf == NULL) {
        return -1;
    }
    for (i = offset; i < window; i++) {
        if (w[i]->ack == 0) {
            /* encode packet in temporary buffer */
            memset(temp_buf, '\0', temp_buflen);
            if (pkt_encode(w[i]->pkt, temp_buf, &temp_buflen) != PKT_OK) {
                ERROR("fail to encode pkt");
                return -1;
            }
            if (send(socket, temp_buf, temp_buflen, 0) == -1) {
                ERROR("Failed to send package %zu", i);
                return -1;
            }
            w[i]->sent = 1;
            sent++;
        }
    }
    free(temp_buf);
    temp_buf = NULL;
    return 0;
}


int
main(int argc, char **argv)
{
    int     have_file = 0;
    char    filename[BUFSIZ];
    int     c;

    if (argc >= 3) {
        while ((c = getopt(argc, argv, "f:")) != -1) {
            switch (c) {
            case 'f':
                memcpy(filename, optarg, strlen(optarg));
                have_file = 1;
                break;
            default:
                help();
                return EXIT_FAILURE;
            }
        }
    }
    /* reinitialize argc so we don't count -f */
    argc -= optind;
    argv += optind;

    /* check that we have enough arguments */
    if (argc < 2) {
        help();
        return EXIT_FAILURE;
    }

    /* check whether input file exists */
    if (have_file && file_exists(filename) == -1) {
        ERROR("File does not exist.\n");
        return EXIT_FAILURE;
    }

    /* resolve the address */
    int port = parse_port(argv[1]);
    if (port == -1) {
        return EXIT_FAILURE;
    }
    struct sockaddr_in6 addr;
    const char *err = real_address(argv[0], &addr);
    if (err) {
        ERROR("Could not resolve hostname or ip : %s\n", err);
        return EXIT_FAILURE;
    }

    /* connect to the socket */
    int sfd = create_socket(NULL, -1, &addr, port);
    if (sfd < 0) {
        ERROR("Failed to create socket.\n");
    }

    /* get data */
    size_t total_len = 0;
    FILE *f = have_file ? open_file(filename, 0) : stdin;
    /* XXX stdin */
    total_len = file_size(f);

    /* get amount of packets needed */
    size_t nb_packets = nb_pkt_in_buffer(total_len);

    printf("amount of packets needed for %zu will be %zu\n", total_len, nb_packets);

    /* XXX DATA TRANSFER TO IMPLEMENT XXX */


    /* cleanup and exit */
    if (have_file) {
        fclose(f);
    }
    close(sfd);

    return EXIT_SUCCESS;
}
