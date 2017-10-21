/**
 * Sender program.
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
 * Slide array elements left
 */
static int
array_slide(pkt_t *a[], size_t size)
{
    if (size > 1) { /* slide elements if there are any */
        size_t i = 1;
        for (; i < size; i++)
            /* pointers, baby */
            *(a + i - 1) = *(a + i);
    }
    return 0;
}

/*
 * Read the file or a buffer from offset and during length bytes onto buf
 */
static char*
get_payload(FILE *f, char *data, size_t *data_offset,
    size_t *left_to_copy, size_t *length)
{
    /* First find out how much we need to get */
    *length = MAX_PAYLOAD_SIZE;
    if (*left_to_copy < MAX_PAYLOAD_SIZE)
        *length = *left_to_copy;

    char *buf = malloc(*length);
    if (buf == NULL) {
        ERROR("Failed to allocate buffer");
        return NULL;
    }
    memset(buf, 0, *length);
    if (f != NULL) {
        file_set_position(f, *data_offset);
        size_t readf = fread(buf, sizeof(char), *length, f);
        if (readf <= 0) {
            ERROR("Failed to read file from byte %zu to %zu\n",
                *data_offset, *data_offset + *length);
            free(buf);
            buf = NULL;
            return NULL;
        }
    }

    if (data != NULL) {
        memcpy(buf, data + *data_offset, *length);
    }
    *data_offset  += *length;
    *left_to_copy -= *length;

    return buf;
}

/*
 *
 * Sliding window mechanic
 *
 */
static void
slide_window(pkt_t *sliding_window[], FILE *f, char *data,
    size_t *data_offset, size_t *left_to_copy,
    uint8_t *seqnum, uint8_t window)
{
    /* delete the first element */
    pkt_del(sliding_window[0]);

    /* move all elements one slot left */
    array_slide(sliding_window, MAX_PAYLOAD_SIZE);

    /* read a pkt from file */
    size_t length = 0;
    char *buf = get_payload(f, data, data_offset, left_to_copy, &length);

    /* fill all fields of new pkt */
    size_t lastel = MAX_WINDOW_SIZE - 1;
    sliding_window[lastel] = pkt_new();
    /* set timestamp XXX */
    pkt_create(sliding_window[lastel], PTYPE_DATA, *seqnum, window, length, 0, buf);

    increment_seqnum(seqnum);

    free(buf);
    buf = NULL;
}

/*
 *
 * Build initial window
 * FIXME maybe re-use allocated pkt_t instead of pkt_new() everytime.
 */
static int
make_window(pkt_t *sliding_window[], FILE *f, char *data,
    size_t total_pkt_to_send,
    size_t *data_offset, size_t *left_to_copy,
    uint8_t *seqnum, uint8_t window)
{
    size_t i = 0;
    for (; i < MAX_WINDOW_SIZE; i++) {
        /* stop if the window size is bigger than file size */
        if (i >= total_pkt_to_send)
            break;

        sliding_window[i] = pkt_new();

        size_t length = 0;
        char *buf = get_payload(f, data, data_offset, left_to_copy, &length);

        /* timestamp XXX */
        pkt_create(sliding_window[i], PTYPE_DATA, *seqnum, window, length, 0, buf);

        increment_seqnum(seqnum);

        free(buf);
        buf = NULL;
    }
    return i;
}

/*
 *
 * Send last packet with a length of zero to terminate the transfer.
 *
 */
static void
send_terminating_packet(int sfd, uint8_t seqnum) {
    size_t len = sizeof(pkt_t);
    char *buf = malloc(len);
    /* XXX functionalise */
    memset(buf, 0, len);
    pkt_t *end_pkt = pkt_new();
    pkt_set_type(end_pkt, PTYPE_DATA);
    pkt_set_seqnum(end_pkt, seqnum);
    if (pkt_encode(end_pkt, buf, &len) != PKT_OK) {
        ERROR("Failed to encode end_pkt");
        goto end;
    }
    if (send(sfd, buf, sizeof(pkt_t), 0) == -1) {
        ERROR("Failed to send end_pkt");
        goto end;
    }

    char *ack_buf = malloc(ACK_PKT_SIZE);
    if (ack_buf == NULL) {
        ERROR("Failed to allocate response_buf");
        goto end;
    }
    pkt_t *ack = pkt_new();
    struct pollfd fds[] = { { sfd, POLLIN|POLLPRI, 0 } };

    int ev = poll(fds, 1, 2000);
    if (ev == -1) {
        ERROR("Poll failed %s", strerror(errno));
        goto end;
    } else if (ev == 0) {
        INFO("Failed to receive ACK for terminating pkt, resending...");
        ssize_t rec = recv(sfd, ack_buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rec == -1) {
            INFO("Client must have disconnected, bye! (%s).", strerror(errno));
        }
        free(buf);
        buf = NULL;
        pkt_del(ack);
        free(ack_buf);
        ack_buf = NULL;
        if (rec != -1) {
            send_terminating_packet(sfd, seqnum);
        }
    } else {
        /* XXX functinalise */
        memset(ack_buf, '\0', ACK_PKT_SIZE);
        if (recv(sfd, ack_buf, ACK_PKT_SIZE, 0) == -1) {
            ERROR("Failed to receive an ack");
            goto ack;
        }
        if (pkt_decode(ack_buf, ACK_PKT_SIZE, ack) != PKT_OK) {
            ERROR("Failed to decode ack");
            goto ack;
        }
        if (pkt_get_type(ack) == PTYPE_ACK) {
            LOG("ACK for terminating packet received.");
            goto ack;
        }
    }
end:
    pkt_del(end_pkt);
    free(buf);
    buf = NULL;
    return;
ack:
    pkt_del(ack);
    free(ack_buf);
    ack_buf = NULL;
    goto end;
}

/*
 * Returns 1 if left is a successor seqnum of right, 0 otherwise
 */
static int
seqnum_succ(uint8_t left, uint8_t right) {
    if (left == 255) {
        left = 0;
        return left <= right;
    } else {
        return left < right;
    }
}


/*
 * Main send loop
 */
static void
send_data(FILE *f, char *data, size_t total_len, int sfd)
{
    /* Start by finding out how many packets we need to send in total */
    size_t total_pkt_to_send = nb_pkt_in_buffer(total_len);
    LOG("We need to send %zu packages", total_pkt_to_send);

    /* Protocol variables */
    uint8_t seqnum = 0;
    uint8_t window = 1;
    size_t  data_offset = 0;                    /* where we are in the file */
    size_t  left_to_copy = total_len;           /* inverse offset in file */
    size_t  left_to_send = total_pkt_to_send;   /* amount of packets left to
                                                   send */
    size_t  i = 0;
    size_t  cur_slot = 0;                       /* sliding window index */
    size_t  cur_seqnum = 0;
    size_t  cur_window_size = MAX_WINDOW_SIZE; /* keep the count of allocated
                                                  packets in the send buffer
                                                  so we can cleanup properly.*/
    int	    keep_sending = 1;
    pkt_t   *sliding_window[MAX_WINDOW_SIZE];   /* send buffer */

    /* Build the initial sliding window */
    cur_window_size = make_window(sliding_window, f, data,
        total_pkt_to_send, &data_offset,
        &left_to_copy, &seqnum, window);

    struct pollfd fd[] = { { sfd, POLLIN|POLLPRI, 0 } };

    /* Main loop */
    while (keep_sending) {
        if (left_to_send == 0) {
            keep_sending = 0;
            continue;
        }
        char *buf = malloc(MAX_PKT_SIZE);
        size_t len = MAX_PKT_SIZE;

        /* Send the packet */
        if (window == 0) {
            LOG("Window is full, we need some ACKs");
        } else {
            window--;
            /* XXX functionalise */
            memset(buf, '\0', MAX_PKT_SIZE);
            if (pkt_encode(sliding_window[cur_slot], buf, &len) != PKT_OK) {
                ERROR("Failed to encode packet %zu", cur_seqnum);
                keep_sending = 0;
            }

            if (keep_sending && send(sfd, buf, len, 0) == -1) {
                ERROR("Failed to send pkt %zu", cur_seqnum);
                keep_sending = 0;
            }
        }

        /* Poll for incoming data 2s */
        int ev = poll(fd, 1, 2000);

        if (ev == -1) {
            ERROR("Poll failed %s", strerror(errno));
            return;
        } else if (ev == 0) {
            INFO("Time-out, we have not received an ACK in the last 2seconds");
            /* Deal with the loss of the first packet */
            if (window == 0)
                window++;
        } else {
            /* Listen for an ACK */
            char *response_buf = malloc(ACK_PKT_SIZE);
            pkt_t *ack = pkt_new();
            /* XXX functinalise */
            memset(response_buf, '\0', ACK_PKT_SIZE);
            if (recv(sfd, response_buf, ACK_PKT_SIZE, 0) == -1) {
                ERROR("Failed to receive an ack");
                keep_sending = 0;
            }
            if (pkt_decode(response_buf, ACK_PKT_SIZE, ack) != PKT_OK) {
                ERROR("Failed to decode ack");
                keep_sending = 0;
            }
            if (pkt_get_type(ack) == PTYPE_ACK) {
                LOG("ACK for packet %zu", cur_seqnum);
                /* XXX check for out of sequence ACKs? */
                left_to_send--;
                /* If we have >= MAX_WINDOW_SIZE packets left to send
                 * and the ack seqnum is a successor then we can slide
                 * the window. This takes in account cumulative acks.
                 */
                if (left_to_send >= MAX_WINDOW_SIZE &&
                    seqnum_succ(pkt_get_seqnum(sliding_window[0]),
                        pkt_get_seqnum(ack))) {
                    cur_seqnum = pkt_get_seqnum(ack);
                    window = pkt_get_window(ack);
                    LOG("cur_seqnum = %zu, cur_slot = %zu, left_to_send = %zu", cur_seqnum, cur_slot, left_to_send);
                    /* Slide window XXX enable sliding by more than one slot at once, cumulative acks */
                    slide_window(sliding_window, f, data,
                        &data_offset, &left_to_copy, &seqnum, window);
                    /* If we don't need to slide the window,
                     * if the current buffer is smaller than max window size
                     */
                } else if (left_to_send > 0) {
                    LOG("cur_seqnum = %zu, cur_slot = %zu, left_to_send = %zu", cur_seqnum, cur_slot, left_to_send);
                    cur_seqnum = seqnum = pkt_get_seqnum(ack);
                    window = pkt_get_window(ack);
                    cur_slot++;
                    cur_window_size = cur_slot + 1;
                } else {
                    keep_sending = 0;
                }
                /* Deal with NACKs, go back to the truncated pkt */
            } else if (pkt_get_type(ack) == PTYPE_NACK) {
                cur_slot = pkt_get_seqnum(ack) % MAX_WINDOW_SIZE;
            }
            pkt_del(ack);
            free(response_buf);
            response_buf = NULL;
        }

        free(buf);
        buf = NULL;
    }

    /* Cleanup */
    for (i = 0; i < cur_window_size; i++) {
        pkt_del(sliding_window[i]);
    }

    /* Finish transmission */
    send_terminating_packet(sfd, seqnum);
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
        return EXIT_FAILURE;
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

    /* start sending the data */
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
