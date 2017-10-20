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
static int
get_payload(char **buf, FILE *f, char *data, size_t offset, size_t length)
{
    char tmp[length];
    memset(tmp, 0, length);
    if (f != NULL) {
        file_set_position(f, offset);
        size_t readf = fread(tmp, sizeof(char), length, f);
        if (readf <= 0) {
            ERROR("Failed to read file from byte %zu to %zu\n", offset, offset + length);
            return -1;
        }
    }

    if (data != NULL) {
        memcpy(&tmp, data + offset, length);
    }

    memcpy(*buf, tmp, length);
    return 0;
}

/*
 *
 * Sliding window mechanic
 *
 */
static void
slide_window(pkt_t *sliding_window[], FILE *f, char *data,
    size_t *nb_pkt, size_t total_pkt_to_send,
    size_t *data_offset, size_t *left_to_copy,
    uint8_t *seqnum, uint8_t window)
{
    if (*nb_pkt >= total_pkt_to_send)
        return;

    /* delete the first element */
    pkt_del(sliding_window[0]);

    /* move all elements one slot left */
    array_slide(sliding_window, MAX_PAYLOAD_SIZE);

    /* read a pkt from file */
    char *buf;
    size_t length = MAX_PAYLOAD_SIZE;
    if (*left_to_copy < MAX_PAYLOAD_SIZE)
        length = *left_to_copy;
    //if (length == 0) return;
    buf = malloc(length);
    memset(buf, '\0', length);
    get_payload(&buf, f, data, *data_offset, length);

    /* fill all fields of new pkt */
    /* XXX merge with make_window */
    size_t lastel = MAX_WINDOW_SIZE - 1;
    sliding_window[lastel] = pkt_new();
    pkt_set_type(sliding_window[lastel], PTYPE_DATA);
    pkt_set_seqnum(sliding_window[lastel], *seqnum);
    pkt_set_window(sliding_window[lastel], window);
    pkt_set_payload(sliding_window[lastel], buf, length);
    pkt_set_crc1(sliding_window[lastel], pkt_gen_crc1(sliding_window[lastel]));
    pkt_set_crc2(sliding_window[lastel], pkt_gen_crc2(sliding_window[lastel]));
    /* set timestamp XXX */

    /* Bookkeeping */
    *data_offset += length;
    *left_to_copy -= length;
    if (*seqnum + 1 >= MAX_SEQNUM)
        *seqnum = 0;
    else (*seqnum)++;
    (*nb_pkt)++;
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
    size_t *nb_pkt, size_t total_pkt_to_send,
    size_t *data_offset, size_t *left_to_copy,
    uint8_t *seqnum, uint8_t window)
{
    struct timeval current_time = {0};
    size_t i = 0;
    for (; i < MAX_WINDOW_SIZE; i++) {
        /* stop if the window size is bigger than file size */
        if (i >= total_pkt_to_send)
            break;

        sliding_window[i] = pkt_new();
        char *buf;

        pkt_set_type(sliding_window[i], PTYPE_DATA);
        pkt_set_tr(sliding_window[i], 0);
        pkt_set_seqnum(sliding_window[i], *seqnum);
        pkt_set_window(sliding_window[i], window);
        update_time(&current_time);
        pkt_set_timestamp(sliding_window[i], pack_timestamp(current_time));

        size_t length = MAX_PAYLOAD_SIZE;
        if (*left_to_copy < MAX_PAYLOAD_SIZE)
            length = *left_to_copy;
        if (length == 0) break;
        buf = malloc(length);
        memset(buf, '\0', length);
        get_payload(&buf, f, data, *data_offset, length);
        pkt_set_payload(sliding_window[i], buf, length);
        pkt_set_crc1(sliding_window[i], pkt_gen_crc1(sliding_window[i]));
        pkt_set_crc2(sliding_window[i], pkt_gen_crc2(sliding_window[i]));

        /* Bookkeeping */
        *data_offset += length;
        *left_to_copy -= length;
        if (*seqnum + 1 >= MAX_SEQNUM)
            *seqnum = 0;
        else (*seqnum)++;

        free(buf);
        buf = NULL;
        (*nb_pkt)++;
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
    memset(buf, 0, len);
    pkt_t *end_pkt = pkt_new();
    pkt_set_type(end_pkt, PTYPE_DATA);
    pkt_set_seqnum(end_pkt, seqnum);
    if (pkt_encode(end_pkt, buf, &len) != PKT_OK) {
        LOG("seqnum of pkt to be written %d", pkt_get_seqnum(end_pkt));
        ERROR("Failed to encode end_pkt");
        goto end;
    }
    if (send(sfd, buf, sizeof(pkt_t), 0) == -1) {
        ERROR("Failed to send end_pkt");
        goto end;
    }

end:
    pkt_del(end_pkt);
    free(buf);
    buf = NULL;
}

/*
 * Returns 1 if left is a successor seqnum of right, 0 otherwise
 *
 */
static int
seqnum_succ(uint8_t left, uint8_t right) {
    LOG("Comparing %d and %d", left, right);
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
    uint8_t  seqnum = 0;
    uint8_t  window = 1;
    size_t  nb_pkt = 0;
    size_t  data_offset = 0;
    size_t  left_to_copy = total_len;
    size_t  left_to_send = total_pkt_to_send;
    size_t  i = 0;
    size_t  cur_slot = 0;
    size_t  cur_seqnum = 0;
    size_t  cur_window_size = MAX_WINDOW_SIZE;
    int	    keep_sending = 1;
    pkt_t   *sliding_window[MAX_WINDOW_SIZE];

    /* Build the initial sliding window */
    cur_window_size = make_window(sliding_window, f, data, &nb_pkt,
        total_pkt_to_send, &data_offset,
        &left_to_copy, &seqnum, window);

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

        /* Listen for an ACK */
        char *response_buf = malloc(ACK_PKT_SIZE);
        pkt_t *ack = pkt_new();
        memset(response_buf, '\0', ACK_PKT_SIZE);
        if (recv(sfd, response_buf, ACK_PKT_SIZE, 0) == -1) {
            ERROR("Failed to receive an ack");
            keep_sending = 0;
        }
        if (pkt_decode(response_buf, ACK_PKT_SIZE, ack) != PKT_OK) {
            ERROR("Failed to decode ack");
            keep_sending = 0;
        }
        /* XXX handle NACKs */
        if (pkt_get_type(ack) == PTYPE_ACK) {
                LOG("ACK for packet %zu", cur_seqnum);
                left_to_send--;
                /*
                 * If we have >= MAX_WINDOW_SIZE packets left to send
                 * and the ack seqnum is a successor then we can slide
                 * the window. This takes in account cumulative acks.
                 */
                if (left_to_send >= MAX_WINDOW_SIZE &&
                    seqnum_succ(pkt_get_seqnum(sliding_window[0]),
                            pkt_get_seqnum(ack))) {
                    cur_seqnum = pkt_get_seqnum(ack);
                    LOG("cur_seqnum = %zu, cur_slot = %zu, left_to_send = %zu", cur_seqnum, cur_slot, left_to_send);
                    /* Slide window XXX enable sliding by more than one slot at once, cumulative acks */
                    slide_window(sliding_window, f, data, &nb_pkt,
                                 total_pkt_to_send, &data_offset,
                                 &left_to_copy, &seqnum, window);
                /* If we don't need to slide the window,
                 * that is if the current buffer is smaller than max window size
                 */
                } else if (left_to_send > 0) {
                    LOG("cur_seqnum = %zu, cur_slot = %zu, left_to_send = %zu", cur_seqnum, cur_slot, left_to_send);
                    cur_seqnum = seqnum = pkt_get_seqnum(ack);
                    cur_slot++;
                } else {
                    keep_sending = 0;
                }
#if 0
                /* Old way sliding a whole window at once */
                if (left_to_send > 0 && nb_pkt_win == 0) {
                    cur_slot = 0;
                    for (i = 0; i < MAX_WINDOW_SIZE; i++) {
                        pkt_del(sliding_window[i]);
                    }
                    cur_window_size = make_window(sliding_window, f, data, &nb_pkt,
                        total_pkt_to_send, &data_offset,
                        &left_to_copy, &seqnum, window) + 1;
                    if (left_to_send < MAX_WINDOW_SIZE)
                        nb_pkt_win = left_to_send;
                    else
                        nb_pkt_win = MAX_WINDOW_SIZE;
                }
#endif
        /* Deal with NACKs, go back to the truncated pkt */
        } else if (pkt_get_type(ack) == PTYPE_NACK) {
            cur_slot = pkt_get_seqnum(ack) % MAX_WINDOW_SIZE;
        }

        pkt_del(ack);
        free(buf);
        buf = NULL;
        free(response_buf);
        response_buf = NULL;
    }

    /* Cleanup */
    for (i = 0; i < cur_window_size; i++) {
        pkt_del(sliding_window[i]);
    }

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
