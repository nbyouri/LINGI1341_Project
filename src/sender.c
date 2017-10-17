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


/*
 * Read the file or a buffer from offset and during length bytes onto buf
 */
static int
get_payload(char **buf, FILE *f, char *data, size_t offset, size_t *length)
{
    *buf = malloc(*length);
    if (*buf == NULL) {
        return -1;
    }
    memset(*buf, '\0', *length);

    if (f != NULL) {
        file_set_position(f, offset);
        size_t readf = read_file(f, buf, *length);
        if (readf <= 0) {
            ERROR("Failed to read file\n");
            return -1;
        }
        if (readf < *length) {
            *length = readf;
        }
    }

    if (data != NULL) {
        memcpy(*buf, data + offset, *length);
    }

    return 0;
}

/*
 * Main send loop
 */
static void
send_data(FILE *f, char *data, size_t total_len, int sfd)
{
    /* Start by finding out how many packets we need to send in total */
    size_t total_pkt_to_send = nb_pkt_in_buffer(total_len);

    minqueue_t *pkt_queue = NULL;

    /* Initialize Priority Queue */
    if (!(pkt_queue = minq_new(pkt_cmp)))
        ERROR("Failed to initialize PQ");

    /* Start by building the first window */
    /* We keep 16KB of data in memory always */
    uint8_t seqnum = 0;
    uint8_t window = 1;
    size_t  nb_pkt = 0;
    size_t  data_offset = 0;
    char    *buf = NULL;
    pkt_t *pkt = pkt_new();
    struct timeval current_time = {.tv_sec = 0, .tv_usec = 0};

    for (; nb_pkt < MAX_WINDOW_SIZE; nb_pkt++) {
        if (nb_pkt >= total_pkt_to_send)
            break;

        pkt_set_type(pkt, PTYPE_DATA);
        pkt_set_tr(pkt, 0);
        pkt_set_seqnum(pkt, seqnum);
        pkt_set_window(pkt, window);
        update_time(&current_time);
        pkt_set_timestamp(pkt, pack_timestamp(current_time));

        size_t length = MAX_PAYLOAD_SIZE;
        get_payload(&buf, f, data, data_offset, &length);
        pkt_set_payload(pkt, buf, length);
        pkt_set_crc1(pkt, pkt_gen_crc1(pkt));
        pkt_set_crc2(pkt, pkt_gen_crc2(pkt));

        minq_push(pkt_queue, pkt);

        /* Bookkeeping */
        data_offset += length;
        if (seqnum + 1 >= MAX_SEQNUM)
            seqnum = 0;
        else seqnum++;

        /* XXX update window value if needed */
    }

    buf = realloc(MAX_PKT_SIZE);
    while (nb_pkt >= 0) {
        if (nb_pkt == 0)
            break;

        memset(buf, '\0', MAX_PKT_SIZE);
        // XXX iterate through priority queue ?
        //if (pkt_encode(minqueue_peek))
    }



    /* Cleanup the Priority Queue */
    free(buf);
    buf = NULL;
    pkt_del(pkt);
    minq_del(pkt_queue);
}

#if 0
/*
 * Create send buffer containing everything to send for the current window
 * and the status.
 */
static int
make_window(pkt_t **,
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
#endif


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
                memset(filename, '\0', BUFSIZ);
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
    FILE *f = NULL;
    char *data = NULL;
    if (have_file) {
        f = open_file(filename, 0);
        total_len = file_size(f);
    } else {
        data = NULL;
        total_len = read_stdin(&data);
    }

#if 0
    /* get amount of packets needed */
    size_t nb_packets = nb_pkt_in_buffer(total_len);

    printf("amount of packets needed for %zu bytes read will be %zu\n", total_len, nb_packets);

    char *tmp = malloc(sizeof(char *));
    size_t len = 8;
    get_payload(&tmp, f, data, 10, &len);
    printf("stdin buf from byte 10 to 18 is [%s]\n", tmp);
    get_payload(&tmp, f, data, 18, &total_len);
    free(tmp);
    tmp = NULL;
#endif

    send_data(f, data, total_len, sfd);


    /* cleanup and exit */
    if (have_file) {
        fclose(f);
    } else {
        free(data);
        data = NULL;
    }
    close(sfd);

    return EXIT_SUCCESS;
}
