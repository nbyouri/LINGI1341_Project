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
get_payload(char **buf, FILE *f, char *data, size_t offset, size_t length)
{
    char tmp[length];
    memset(tmp, 0, length);
    if (f != NULL) {
        file_set_position(f, offset);
        size_t readf = fread(tmp, sizeof(char), length, f);
        if (readf <= 0) {
            ERROR("Failed to read file\n");
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
 * Build initial window
 *
 */
static void
make_window(pkt_t *sliding_window[], FILE *f, char *data,
	    size_t *nb_pkt, size_t total_pkt_to_send,
	    size_t *data_offset, size_t *left_to_copy,
	    uint8_t *seqnum, uint8_t window)
{
    struct timeval current_time = {.tv_sec = 0, .tv_usec = 0};
    int i = 0;
    for (; i < MAX_WINDOW_SIZE; i++) {
	/* stop if the window size is bigger than file size */
        if (*nb_pkt >= total_pkt_to_send)
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
}

#if 0
/*
 *
 * Slide the window
 *
 */
static void
slide_window(pkt_t *sliding_window[], FILE *f, char *data,
	     size_t *nb_pkt, size_t *data_offset,
	     size_t *left_to_copy, uint8_t *seqnum, uint8_t window)
{
    char *buf;
    (*nb_pkt)++;
    
    
}
#endif

/*
 *
 * Send last packet with a length of zero to terminate the transfer.
 *
 */
static void
send_terminating_packet(int sfd, uint8_t seqnum) {
    size_t len = sizeof(pkt_t);
    char *buf = malloc(len);
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

end:
    pkt_del(end_pkt);
    free(buf);
    buf = NULL;
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
    size_t  nb_pkt = 0;
    size_t  data_offset = 0;
    size_t  left_to_copy = total_len;
    size_t  left_to_send = total_pkt_to_send;
    size_t  i = 0;
    int	    keep_sending = 1;
    pkt_t   *sliding_window[MAX_WINDOW_SIZE];

    /* Build the initial sliding window */
    make_window(sliding_window, f, data, &nb_pkt,
		total_pkt_to_send, &data_offset,
		&left_to_copy, &seqnum, window);

    LOG("Entering main loop.");
    /* Main loop */
    size_t nb_pkt_win = nb_pkt;
    while (keep_sending) {
	if (nb_pkt_win == 0) {
		keep_sending = 0;
		continue;
	}
	char *buf = malloc(MAX_PKT_SIZE);
	size_t len = MAX_PKT_SIZE;

        /* Send the packet */
	if (window == 0) {
		LOG("The window is full, we need to wait for ACKs");
	} else {
                memset(buf, '\0', MAX_PKT_SIZE);
		if (pkt_encode(sliding_window[seqnum], buf, &len) != PKT_OK) {
			ERROR("Failed to encode packet %d\n", seqnum);
			keep_sending = 0;
		}

		if (keep_sending && send(sfd, buf, len, 0) == -1) {
			ERROR("Failed to send pkt %d\n", seqnum);
			keep_sending = 0;
		}
	}
        LOG("Sent packet");

	/* Listen for an ACK XXX multiplex! */
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
		if (pkt_get_seqnum(ack) == seqnum + 1) {
			LOG("ACK for packet %d", seqnum);
			left_to_send--;
			nb_pkt_win--;
			if (left_to_send > 0) {
				seqnum = pkt_get_seqnum(ack);
				window = pkt_get_window(ack);
			} else {
				keep_sending = 0;
			}
                        /* XXX do a sliding window */
                        if (nb_pkt_win == 0 && left_to_send > 0) {
                            make_window(sliding_window, f, data, &nb_pkt,
                                        total_pkt_to_send, &data_offset,
                                        &left_to_copy, &seqnum, window);
                            nb_pkt_win = MAX_WINDOW_SIZE;
                        }
		} else {
			LOG("Out of sequence ACK (%d)!", pkt_get_seqnum(ack));
		}
	}
	pkt_del(ack);
	free(buf);
	buf = NULL;
	free(response_buf);
	response_buf = NULL;
    }

    /* Cleanup */
    for (i = 0; i < nb_pkt; i++) {
	pkt_del(sliding_window[i]);
    }

    send_terminating_packet(sfd, seqnum);
}

#if 0
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
