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
array_slide(pkt_t *a[], size_t size, int n)
{
    if (size > 1) { /* slide elements if there are any */
        size_t i = n;
        for (; i < size; i++)
            /* pointers, baby */
            *(a + i - n) = *(a + i);
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
slide_window(pkt_t *sliding_window[], FILE *f,
    char *data, size_t *data_offset,
    size_t *left_to_copy, uint8_t *seqnum,
    uint8_t window, int n)
{
    int i = 0;
    /* delete the first elements */
    for (; i < n; pkt_del(sliding_window[i++]));

    /* move all elements one slot left */
    array_slide(sliding_window, MAX_PAYLOAD_SIZE, n);

    /* add new pkt from file if needed */
    if (*left_to_copy > 0) {
        size_t firstel = MAX_WINDOW_SIZE - n;
        for (i = firstel; i < MAX_WINDOW_SIZE; i++) {
            size_t  length = 0;
            char    *buf = get_payload(f, data, data_offset,
                left_to_copy, &length);

            /* fill all fields of new pkt */
            sliding_window[i] = pkt_new();

            pkt_create(sliding_window[i], PTYPE_DATA,
                *seqnum, window, length, buf);

            increment_seqnum(seqnum);

            free(buf);
            buf = NULL;
        }
    }
}

/*
 *
 * Build initial window
 *
 */
static int
make_window(pkt_t *sliding_window[], FILE *f,
    char *data, size_t total_pkt_to_send,
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

        pkt_create(sliding_window[i], PTYPE_DATA,
            *seqnum, window, length, buf);

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
send_terminating_packet(int sfd, uint8_t seqnum, uint8_t window)
{
    size_t  len = sizeof(pkt_t);
    char    *buf = malloc(len);
    memset(buf, 0, len);
    pkt_t *end_pkt = pkt_new();
    pkt_set_type(end_pkt, PTYPE_DATA);
    pkt_set_seqnum(end_pkt, seqnum);
    pkt_set_window(end_pkt, window);
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
        LOG("Failed to receive ACK for terminating pkt, resending...");
        ssize_t rec = recv(sfd, ack_buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rec == -1 && errno == ENOTCONN) {
            LOG("Client must have disconnected, bye! (%s).", strerror(errno));
        }
        free(buf);
        buf = NULL;
        pkt_del(ack);
        free(ack_buf);
        ack_buf = NULL;
        if (rec == -1) {
            send_terminating_packet(sfd, seqnum, window);
        }
    } else {
        memset(ack_buf, '\0', ACK_PKT_SIZE);
        if (recv(sfd, ack_buf, ACK_PKT_SIZE, 0) == -1) {
            ERROR("Failed to receive an ack");
            goto ack;
        }
        if (pkt_decode(ack_buf, ACK_PKT_SIZE, ack) != PKT_OK) {
            LOG("Corrupted terminating ack.");
            goto ack;
        }
        if (pkt_get_type(ack) == PTYPE_ACK) {
            if (pkt_get_seqnum(ack) != seqnum) {
                LOG("Received stale ACK %d, expected %d"
                    "resending...", pkt_get_seqnum(ack),seqnum);
                usleep(200);
                send_terminating_packet(sfd, seqnum, window);
            } else {
                LOG("ACK for terminating packet received.(%d)",
                    pkt_get_seqnum(ack));
            }
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
 * Main send loop
 */
static void
send_data(FILE *f, char *data, size_t total_len, int sfd)
{
    /* Start by finding out how many packets we need to send in total */
    size_t total_pkt_to_send = nb_pkt_in_buffer(total_len);

    /* Protocol variables */
    uint8_t seqnum = 0;
    uint8_t window = 1;
    size_t  data_offset = 0;                    /* where we are in the file */
    size_t  left_to_copy = total_len;           /* inverse offset in file */
    size_t  left_to_send = total_pkt_to_send;   /* amount of packets left to
                                                   send */
    uint8_t cur_seqnum = 0;
    int	    keep_sending = 1;
    pkt_t   *sliding_window[MAX_WINDOW_SIZE];   /* send buffer */

    /* Timing variables */
    struct timeval ct     = {0};
    float          rtt    = 0;                  /* Round-Trip-Time */
    float          srtt   = 0;                  /* Smoothed RTT */
    float          rttvar = 0.75;               /* RTT variance */
    float          rto    = MAX_TIMEOUT;        /* Retransmission Timeout */

    /* Build the initial sliding window */
    make_window(sliding_window, f, data,
        total_pkt_to_send, &data_offset,
        &left_to_copy, &seqnum, window);

    struct pollfd fd[] = { { sfd, POLLIN|POLLPRI, 0 } };

    /* Main loop */
    while (keep_sending) {
        if (left_to_send == 0) {
            keep_sending = 0;
            continue;
        }
        char    *buf = malloc(MAX_PKT_SIZE);
        size_t  len = MAX_PKT_SIZE;

        /* Send the packet */
        if (window == 0) {
            LOG("Window is full, we need some ACKs");
        } else {
            /* Update the timestamp before sending */
            update_time(&ct);
            uint32_t ts = ct.tv_usec;
            LOG("Setting timestamp of %d", ts);
            pkt_set_timestamp(sliding_window[0], ts);
            memset(buf, '\0', MAX_PKT_SIZE);
            if (pkt_encode(sliding_window[0], buf, &len) != PKT_OK) {
                ERROR("Failed to encode packet %d", cur_seqnum);
                keep_sending = 0;
            }

            LOG("Sending pkt %d, window = %d", cur_seqnum, window);
            if (keep_sending && send(sfd, buf, len, 0) == -1) {
                ERROR("Failed to send pkt %d", cur_seqnum);
                keep_sending = 0;
            }
            increment_seqnum(&cur_seqnum);
            window--;
        }

        /* Poll for incoming data */
        int ev = poll(fd, 1, rto/1000);

        if (ev == -1) {
            ERROR("Poll failed %s", strerror(errno));
            return;
        } else if (ev == 0) {
            LOG("Time-out");
            /* Deal with the loss of the first packet */
            if (window == 0)
                window++;
        } else if (ev > 0) {
            /* Listen for an ACK */
            char *response_buf = malloc(ACK_PKT_SIZE);
            pkt_t *ack = pkt_new();
            memset(response_buf, '\0', ACK_PKT_SIZE);
            if (recv(sfd, response_buf, ACK_PKT_SIZE, 0) == -1) {
                ERROR("Failed to receive an ack");
                keep_sending = 0;
            }
            if (pkt_decode(response_buf, ACK_PKT_SIZE, ack) != PKT_OK) {
                LOG("Corrupted packet, ignoring...");
            } else {
                if (pkt_get_type(ack) == PTYPE_DATA || pkt_get_tr(ack) == 1) {
                    LOG("Truncated (n)ack, ignoring...");
                } else if (pkt_get_type(ack) == PTYPE_ACK) {
                    LOG("Got an ack %d", pkt_get_seqnum(ack));
                    /* If the ack seqnum is a successor then we can slide
                     * the window. This takes in account cumulative acks.
                     */
                    if (left_to_send > 0 &&
                        seqnum_succ(pkt_get_seqnum(sliding_window[0]),
                            pkt_get_seqnum(ack))) {
                        /* Find out how much we ned to slide */
                        size_t nb_slide = seqnum_diff(
                            pkt_get_seqnum(sliding_window[0]),
                            pkt_get_seqnum(ack));
                        window = pkt_get_window(ack);
                        cur_seqnum = pkt_get_seqnum(ack);

                        /* Calculate timestamp difference */
                        update_time(&ct);
                        rtt = ct.tv_usec - pkt_get_timestamp(ack);
                        if (total_pkt_to_send == left_to_send) {
                            /* initial srtt and rto calculation */
                            srtt   = rtt;
                            rttvar = rtt / 2;
                            rto    = srtt + 4 * rttvar;
                        } else {
                            /* normal srtt and rto calculations */
                            srtt   = abs(rtt - srtt) / 8;
                            rttvar+= (abs(rtt - srtt) - rttvar) / 4;
                            rto    = srtt + (4 * rttvar);
                        }
                        if (rto > MAX_TIMEOUT * 1000)
                            rto = MAX_TIMEOUT * 1000;

                        slide_window(sliding_window, f, data,
                            &data_offset, &left_to_copy, &seqnum,
                            window, nb_slide);
                        left_to_send -= nb_slide;
                    } else if (left_to_send == 0) {
                        keep_sending = 0;
                    }
                } else if (pkt_get_type(ack) == PTYPE_NACK) {
                    /* Deal with NACKs, go back to the truncated pkt */
                    LOG("NACK received");
                }
            }
            pkt_del(ack);
            free(response_buf);
            response_buf = NULL;
        }

        free(buf);
        buf = NULL;
    }

    /* Finish transmission */
    seqnum++;
    send_terminating_packet(sfd, seqnum, window);
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
