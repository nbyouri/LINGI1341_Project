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

static pkt_t* pkt_reception(int nb_packet){
	pkt_t* pkt = pkt_new();
	if(nb_packet == 0){
		pkt_set_seqnum(pkt,2);
		pkt_set_payload(pkt," world",6);
	}	
	if(nb_packet == 1){
		pkt_set_seqnum(pkt,1);
		pkt_set_payload(pkt,"hello",5);	
	}
	if(nb_packet == 2){
		pkt_set_seqnum(pkt,3);
		pkt_set_length(pkt, 0);	
	}
	return pkt;
}

static void
receive_data(FILE *f, int sfd)
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
		/*XXX method reception pkt*/
			pkt_t *pkt = pkt_reception(nb_packet);
			if(pkt_get_length(pkt) == 0) {
				finish = 1;
				break;
			}
				
			minq_push(pkt_queue, pkt);
			//pkt_del(pkt);
			/*XXX method send ack */	
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
