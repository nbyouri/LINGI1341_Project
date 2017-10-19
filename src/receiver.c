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
	pkt_t* pkt_resp = pkt_new();	
	uint8_t type = 0;
	uint8_t seqnum = 0; 
	if(pkt_get_tr(pkt) == 0){
		type = PTYPE_ACK;
		if(seqnum < MAX_SEQNUM)
			seqnum = pkt_get_seqnum(pkt) + 1;
	}
	else {
		type = PTYPE_NACK;
		seqnum = pkt_get_seqnum(pkt);
	}
		
	
	pkt_resp = pkt_create(type, 0, seqnum, pkt_get_window(pkt), pkt_get_timestamp(pkt), 0, NULL);
	/*XXX send packet**/ 	
		
}



static pkt_t* 
pkt_reception (int nb_packet){
	pkt_t* pkt = pkt_new();
	if(nb_packet == 0){
		pkt = pkt_create(PTYPE_DATA, 0, 2, 1, 6, 0, "world");
	}	
	if(nb_packet == 1){
		pkt = pkt_create(PTYPE_DATA, 0, 1, 1, 5, 0, "hello");
	}
	if(nb_packet == 2){
		pkt = pkt_create(PTYPE_DATA, 0, 3, 1, 0, 0, NULL);
	}
	if(nb_packet == 3){
		pkt = pkt_create(PTYPE_DATA, 0, 4, 1, 7, 0, "garbage");
	}
	return pkt;
}

static void
receive_data (FILE *f, int sfd)
{
	size_t nb_packet = 0;
	int finish = 0;
	char  *buf = malloc(MAX_PKT_SIZE);
	memset(buf, '\0', MAX_PKT_SIZE);
	
	minqueue_t* pkt_queue = NULL;
	if (!(pkt_queue = minq_new(pkt_cmp_seqnum)))
		ERROR("Failed to initialize PQ");
	
	while(!finish) {
		/* Packets reception in priority queue */
		for (; nb_packet < MAX_WINDOW_SIZE; nb_packet++) {
			/*method reception pkt here is just for testing */
			pkt_t *pkt = pkt_reception(nb_packet);
			/*XXX check the packet */			
			minq_push(pkt_queue, pkt);
			
			/** XXX rework to break look */
			if(pkt_get_length(pkt) == 0) {
				finish = 1;
				break;
			}
			/*XXX method send ack or nack */
			send_response(pkt, sfd);	
		}
		/* Empty the priority and append payload to the file*/
		while (!minq_empty(pkt_queue)) {
			if(pkt_get_length(minq_peek(pkt_queue)) == 0)
				break;
			fprintf(f, pkt_get_payload(minq_peek(pkt_queue)));
			minq_pop(pkt_queue);        
		}

	}
	
	
    /* sent length = 0 packet to terminate connection */

   
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
	    receive_data(have_file ? f : stdout, 5);
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

    close(sfd);

#if 0 /* XXX LINUX BUG? */
    if (have_file && f != NULL) {
        fclose(f);
    }
#endif

    return EXIT_SUCCESS;
}
