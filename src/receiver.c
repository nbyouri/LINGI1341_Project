/**
 * Sender program.
 *
 * Nicolas Sias
 *	&
 * Youri Mouton
 *
 * For LINGI1341, October 2017, UCL.
 *
 */
#include "common.h"

static void 
send_response (pkt_t* pkt, int sfd){
	char* buf = NULL;
	pkt_t* pkt_resp = pkt_new();	
	uint8_t type = 0;
	uint8_t seqnum = 0; 
	if (pkt_get_tr(pkt) == 0){
		type = PTYPE_ACK;
	}
	else {
		type = PTYPE_NACK;
	}
	if (seqnum + 1 >= MAX_SEQNUM)
		seqnum = 0;
	else seqnum = pkt_get_seqnum(pkt) + 1;
		
	/**XXX add timestamp */
	pkt_create(pkt_resp, type, 0, seqnum, pkt_get_window(pkt), 0, NULL);
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
		
}

#if 0
static void
pkt_reception (pkt_t* pkt, int nb_packet, char* buf, size_t* len){
	if(nb_packet == 0){
		pkt_create(pkt, PTYPE_DATA, 0, 2, 1, 5, " man!");
	}	
	if(nb_packet == 1){
		pkt_create(pkt, PTYPE_DATA, 0, 1, 1, 2, "my");
	}
	if(nb_packet == 2){
		pkt_create(pkt, 4, 0, 3, 1, 19, "first_garbage545454");
		*buf = "slkfslfslmk";
		return;
	}
	if(nb_packet == 3){
		pkt_create(pkt, PTYPE_DATA, 0, 4, 1, 0, NULL);
	}
	if(nb_packet == 4){
		pkt_create(pkt, PTYPE_DATA, 0, 4, 1, 7, "garbage");
	}
	pkt_encode(pkt, buf, *len);
	
}
#endif

static void
receive_data (FILE *f, int sfd)
{
	pkt_status_code status = 0;
	size_t nb_packet = 0;
	int finish = 0;
	
	minqueue_t* pkt_queue = NULL;
	if (!(pkt_queue = minq_new(pkt_cmp_seqnum))) {
		ERROR("Failed to initialize PQ");
		return;
	}
	
	while (!finish) {
		/* Packets reception in priority queue */
		for (; nb_packet < MAX_WINDOW_SIZE; nb_packet++) {
			if (finish) break;
			/* Receive data */
			char buf[MAX_PKT_SIZE];
			
			ssize_t read = recv(sfd, buf, MAX_PKT_SIZE, 0);
			if (read == -1) {
				ERROR("Failed to receive");
				break;
			}
			/*Treat data */
			pkt_t* pkt = pkt_new();
			status = pkt_decode(buf, read, pkt);
			/*XXX check the packet */
			if (status == PKT_OK) {
				/** XXX rework to break look */
				if(pkt_get_length(pkt) == 0) {
					finish = 1;
					pkt_del(pkt);
					break;
				}
				if (minq_push(pkt_queue, pkt)) {
					ERROR("Failed to add pkt to queue.");
					return;
				}
				/*XXX method send ack or nack */
				send_response(pkt, sfd);	
			}			
		}
		/* Empty the priority and append payload to the file*/
		while (!minq_empty(pkt_queue)) {
			pkt_t *pkt = (pkt_t *)minq_peek(pkt_queue);
			size_t len = pkt_get_length(pkt);
			write_file(f, pkt_get_payload(pkt), len);
			minq_pop(pkt_queue);        
			pkt_del(pkt);
		}

	}
	minq_del(pkt_queue);
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


#if 0
        /* treat data */
        LOG("Treating data");
        size_t i = 0;
        for (; buffer[i] != NULL && i < MAX_WINDOW_SIZE; i++) {
            if (pkt_get_length(buffer[i]) > 0) {
                fwrite(pkt_get_payload(buffer[i]), sizeof(char),
                    pkt_get_length(buffer[i]), have_file ? f : stdout);
                bytes_written += pkt_get_length(buffer[i]);
                good_seqnum++;
            }
        }
        LOG("bytes_written = %zu", bytes_written);
#endif
    receive_data(have_file ? f : stdout, sfd);
    close(sfd);

#if 0 /* XXX LINUX BUG? */
    if (have_file && f != NULL) {
        fclose(f);
    }
#endif

    return EXIT_SUCCESS;
}
