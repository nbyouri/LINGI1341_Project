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
send_response (pkt_t* pkt, int sfd, uint8_t window){
    char* buf = NULL;
    pkt_t* pkt_resp = pkt_new();
    uint8_t type = 0;
    uint8_t seqnum = pkt_get_seqnum(pkt);
    if (pkt_get_tr(pkt) == 0){
        type = PTYPE_ACK;
    }
    else {
        type = PTYPE_NACK;
    }
    //LOG("Send packet ack seqnum %d", seqnum);
    if (seqnum + 1 >= MAX_SEQNUM)
        seqnum = 0;
    else seqnum = seqnum + 1 ;
    LOG("ACK Seqnum sent : %d", seqnum);
    LOG("ACK Window : %d \n", window);
    /*XXX Timestamp => last pkt received */
    pkt_create(pkt_resp, type, 0, seqnum, window, 0, pkt_get_timestamp(pkt), NULL);
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
    size_t nb_packet = 0;
    int keep_receiving = 1;
    uint8_t last_seqnum = 0;
    uint8_t window = MAX_WINDOW_SIZE;
    minqueue_t* pkt_queue = NULL;
    if (!(pkt_queue = minq_new(pkt_cmp_seqnum, pkt_cmp_seqnum2))) {
        ERROR("Failed to initialize PQ");
        return;
    }

    while (keep_receiving) {
        /* Packets reception in priority queue */
        LOG("Begin for");
        for (nb_packet = 0; nb_packet < MAX_WINDOW_SIZE; nb_packet++) {
            if (!keep_receiving) break;
            /* Receive data */
            char buf[MAX_PKT_SIZE];
            ssize_t read = recv(sfd, buf, MAX_PKT_SIZE, 0);
            if (read == -1) {
                LOG("Read finish => failed to receive or end receiving");
                ERROR("Failed to receive");
                keep_receiving = 0;
                break;
            }
            /*Treat data */
            pkt_t* pkt = pkt_new();
            status = pkt_decode(buf, read, pkt);
            if (status == PKT_OK) {
                /** XXX packet TR = 1 */
                /** XXX rework to break look => && last_seqnum == pkt_get_seqnum(pkt) */
                if(pkt_get_length(pkt) == 0 && last_seqnum == pkt_get_seqnum(pkt)) {
                    LOG("Seqnum length 0 : %d", pkt_get_seqnum(pkt)); 
                    keep_receiving = 0;
                    pkt_del(pkt);
                    break;
                }
                last_seqnum = pkt_get_seqnum(pkt);

                LOG("Last seqnum received : %d", last_seqnum);
                send_response(pkt, sfd, --window);

                if (minq_push(pkt_queue, pkt)) {
                    ERROR("Failed to add pkt to queue.");
                    return;
                }
                if (last_seqnum + 1 == MAX_SEQNUM)
                    break;


            }
        }
        /* Empty the priority and append payload to the file*/
        while (!minq_empty(pkt_queue)) {
            pkt_t *pkt = (pkt_t *)minq_peek(pkt_queue);
            size_t len = pkt_get_length(pkt);
            write_file(f, pkt_get_payload(pkt), len);
            minq_pop(pkt_queue);
            pkt_del(pkt);
            window ++;
        }

    }
    LOG("end main loop..Close program");
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
