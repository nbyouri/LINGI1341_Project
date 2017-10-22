/**
 * Receiver program.
 *
 * Nicolas Sias
 *	&
 * Youri Mouton
 *
 * For LINGI1341, October 2017, UCL.
 *
 */
#include "common.h"

/*
 * Fill window and check which packet is missing
 * return 1 to authorize the writing, else 0
 */

static int
fill_window(minqueue_t *pkt_queue, pkt_t* pkt, size_t* window_size, uint8_t* min_missing_pkt) {
    uint8_t actual_seqnum = pkt_get_seqnum(pkt);
    if (minq_push(pkt_queue, pkt)) {
        ERROR("Failed to add pkt to queue.");
        return 0;
    }
    if (actual_seqnum == *min_missing_pkt) {
        increment_seqnum(min_missing_pkt);
        (*window_size)--;
        return 1;
    }
    /* Check if the packet is not out sequenced */
    if((*min_missing_pkt - actual_seqnum) < MAX_WINDOW_SIZE)
        (*window_size)--;
    
    return 0;
    
}

/* Empty the priority queue and append payload to the file*/
static int
write_packet(FILE *f, minqueue_t *pkt_queue, size_t *window_size, uint8_t *seqnum_to_send, ssize_t* last_seqnum_written, uint8_t* min_missing_pkt) {
    int keep_writing = 1;
    uint8_t last_seqnum = 0;
    while (!minq_empty(pkt_queue) && keep_writing) {
        pkt_t *pkt = (pkt_t *)minq_peek(pkt_queue);
        size_t len = pkt_get_length(pkt);
        uint8_t actual_seqnum = pkt_get_seqnum(pkt);
	if(*min_missing_pkt < actual_seqnum) {
	    LOG("Writing stopped, wait for missing packet, seqnum %d", *min_missing_pkt);
	    keep_writing = 0;	
	}
	else {
	    if (*last_seqnum_written != actual_seqnum) {
	    	write_file(f, pkt_get_payload(pkt), len);
		*last_seqnum_written = actual_seqnum;
	    }
	    minq_pop(pkt_queue);
	    (*window_size)++;
	    if (*min_missing_pkt == actual_seqnum)
                increment_seqnum(min_missing_pkt);
	    
	    last_seqnum = actual_seqnum;
	}
	    
            pkt_del(pkt);
        }
        increment_seqnum(&last_seqnum);
	/* Check if we sent this ACK */
	if (*seqnum_to_send == last_seqnum)
	    return 0;
	else {
	    *seqnum_to_send = last_seqnum;
	    return 1;
	}
} 


/* XXX ACK cumul **/
static void
send_response(pkt_t *pkt, int sfd, uint8_t seqnum, uint8_t window){
    char* buf = NULL;
    pkt_t* pkt_resp = pkt_new();
    uint8_t type = 0;
    if (pkt_get_tr(pkt) == 0){
        type = PTYPE_ACK;
    }
    else {
        type = PTYPE_NACK;
    }
    //LOG("Send packet ack seqnum %d", seqnum);
    LOG("ACK Seqnum sent : %d", seqnum);
    LOG("ACK Window : %d", window);
    /*XXX Timestamp => last pkt received */
    pkt_create(pkt_resp, type, seqnum, window, 0, pkt_get_timestamp(pkt), NULL);
    size_t len = ACK_PKT_SIZE;
    buf = malloc(len);
    memset(buf, '\0', len);
    if (pkt_encode(pkt_resp, buf, &len) != PKT_OK){
        ERROR("Encode ACK/NACK packet failed");
        return;
    }
    if (send(sfd, buf, len, 0) == -1) {
        ERROR("Send ACK/NACK packet failed");
        return;
    }
    free(buf);
    buf = NULL;
    pkt_del(pkt_resp);
}


static void
receive_data (FILE *f, int sfd)
{
    pkt_status_code status = 0;
    int keep_receiving = 1;
    int ready_to_write = 0;
    int ready_to_send = 0;
    size_t window_size = MAX_WINDOW_SIZE - 1;
    ssize_t last_seqnum_written = -1;
    uint8_t seqnum_ack = 0;
    uint8_t min_missing_pkt = 0;
    minqueue_t* pkt_queue = NULL;
    struct pollfd fds[]= {{sfd, POLLIN | POLLPRI, 0}};
    if (!(pkt_queue = minq_new(pkt_cmp_seqnum, pkt_cmp_seqnum2))) {
        ERROR("Failed to initialize PQ");
        return;
    }

    while (keep_receiving) {
        /* Packets reception in priority queue */
        if (!keep_receiving) break;
	int ev = poll(fds, 1, 2000);
	if (ev == -1) {
	    ERROR("Poll failed");
	    break;
	}
	else if (ev == 0) {
	    LOG("Time out...Waiting for more packets");	
	}
	else {	
	/* Receive data */
		char buf[MAX_PKT_SIZE];
		ssize_t read = recv(sfd, buf, MAX_PKT_SIZE, 0);
		if (read == -1) {
		    ERROR("Error receiving");
		    keep_receiving = 0;
		    continue;
		}
		/*Treat data */
		pkt_t* pkt = pkt_new();
		status = pkt_decode(buf, read, pkt);
		/* Check if the packet is corrupted */
		if (pkt_gen_crc1(pkt) != pkt_get_crc1(pkt))
			status = E_CRC;
		if (pkt_gen_crc2(pkt) != pkt_get_crc2(pkt))
			status = E_CRC;
		if (status == PKT_OK) {
		    /** XXX rework to break look ? */
		    if (pkt_get_length(pkt) == 0 && last_seqnum_written == pkt_get_seqnum(pkt)) {
			send_response(pkt, sfd, 0, window_size); 
		        keep_receiving = 0;
		        pkt_del(pkt);
		        continue;
		    }
		    /* Send NACK and ignore packet if it's truncated */
		    if (pkt_get_tr(pkt) == 1){
		    	send_response(pkt, sfd, pkt_get_seqnum(pkt), window_size);
			continue;
		    }
		    ready_to_write = fill_window( pkt_queue, pkt, &window_size, &min_missing_pkt);
		    if(ready_to_write)
		    	ready_to_send = write_packet(f, pkt_queue, &window_size, &seqnum_ack, &last_seqnum_written, &min_missing_pkt);
		    if(ready_to_send)
			send_response(pkt, sfd, seqnum_ack, window_size);
		   
		   }
		else
		    LOG("Corrupted packet");
        }
    }
    minq_del(pkt_queue);
    LOG("End of transaction");
}

int
main(int argc, char **argv)
{
    int     have_file = 0;
    char    filename[BUFSIZ];
    int     d;

    if (argc >= 3) {
        while ((d = getopt(argc, argv, "f:")) != -1) {
            switch (d) {
            case 'f':
                memset(filename, 0, BUFSIZ);
                memcpy(filename, optarg, strlen(optarg));
                have_file = 1;
                break;
            default:
                help();
                return EXIT_FAILURE;
            }
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 2) {
        help();
        return EXIT_FAILURE;
    }

    /* check whether output file exists */
    FILE    *f = NULL;
    if (have_file && file_exists(filename) == 0) {
        ERROR("File alread exists.\n");
        return EXIT_FAILURE;
    } else if (have_file) {
        f = open_file(filename, 1);
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

    /* bind to the socket */
    int sfd = create_socket(&addr, port, NULL, -1);
    if (sfd > 0 && wait_for_client(sfd) < 0) {
        ERROR("Could not connect the socket after the first packet.\n");
        close(sfd);
        return EXIT_FAILURE;
    }

    receive_data(have_file ? f : stdout, sfd);

    return EXIT_SUCCESS;
}
