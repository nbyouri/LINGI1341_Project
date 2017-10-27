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
/* Add correct packet to the queue and decrement window_size */
static void
add_to_window(minqueue_t *pkt_queue, pkt_t *pkt, size_t *window_size,
  uint8_t *min_seqnum_missing)
{
  /*If the packet added is the min_missing packet, increment it*/
  if (*min_seqnum_missing == pkt_get_seqnum(pkt)) {
    increment_seqnum(min_seqnum_missing);
        LOG("Increment seqnum when add queue :%d", *min_seqnum_missing);
  }

  if(minq_push(pkt_queue,pkt)) {
    ERROR("Failed to add pkt queue");
    return;
  }
  (*window_size)--;
}

/* Write packets and pop them in the queue if they're written */
static void
write_packet(FILE *f,minqueue_t *pkt_queue, ssize_t *last_seqnum_written,
size_t *window_size, uint8_t *min_seqnum_missing) {
    pkt_t *pkt = (pkt_t *)minq_peek(pkt_queue);
    while (pkt && seqnum_diff(*last_seqnum_written, pkt_get_seqnum(pkt)) == 1) {
      /* Write if the seqnum is the next seqnum expected */
        LOG("Writing seq %d", pkt_get_seqnum(pkt));
        write_file(f, pkt_get_payload(pkt), pkt_get_length(pkt));
        *last_seqnum_written = pkt_get_seqnum(pkt);
        (*window_size)++;
        minq_pop(pkt_queue);
        pkt_del(pkt);
        pkt = (pkt_t *)minq_peek(pkt_queue);
    }
    /* Update newest min missing seqnum */
    if (*last_seqnum_written >= *min_seqnum_missing) {
      *min_seqnum_missing = *last_seqnum_written;
      increment_seqnum(min_seqnum_missing);
    }
}

/* General function for sending ACK/NACK */
static void
send_response(uint8_t tr, uint8_t seqnum,
  size_t window_size, uint32_t last_timestamp, int sfd) {
    char    *buf = NULL;
    pkt_t   *pkt = pkt_new();
    uint8_t type = 0;
    /* Define if the response is a ACK or a NACK packet */
    if (tr == 0){
        LOG("ACK Seqnum sent : %d", seqnum);
        type = PTYPE_ACK;
    } else {
        LOG("NACK Seqnum sent : %d", seqnum);
        type = PTYPE_NACK;
    }
    LOG("Window size sent : %zd \n", window_size);
    /* Prepare the packet and send it */
    pkt_create(pkt, type, seqnum, window_size, 0, last_timestamp, NULL);
    size_t len = ACK_PKT_SIZE;
    buf = malloc(len);
    memset(buf, '\0', len);
    if (pkt_encode(pkt, buf, &len) != PKT_OK){
        ERROR("Encode ACK/NACK packet failed");
        return;
    }
    if (send(sfd, buf, len, 0) == -1) {
        ERROR("Send ACK/NACK packet failed");
        return;
    }
    free(buf);
    buf = NULL;
    pkt_del(pkt);

}
/* Main loop for receiving data */
static void
receive_data(FILE *f, int sfd)
{
  pkt_status_code status = PKT_OK;
  int keep_receiving = 1;
  int pkt_ready_for_queue = 0;
  size_t window_size = MAX_WINDOW_SIZE - 1;
  ssize_t last_seqnum_written = -1;
  uint32_t last_timestamp = 0;      /* Last timestamp from the packet received*/
  uint8_t tr = 0;                   /* Tr from the packet received */
  uint8_t min_seqnum_missing = 0;   /* Min seqnum packet sequenced needed */
  minqueue_t* pkt_queue = NULL;     /* Minimum oriented priority queue serving
                                       received buffer */
  if (!(pkt_queue = minq_new(pkt_cmp_seqnum, pkt_cmp_seqnum2))) {
      ERROR("Failed to initialize PQ");
      return;
  }
  struct pollfd fds[]= {{sfd, POLLIN | POLLPRI, 0}};

  while(keep_receiving) {
    /* Wait infinitely for new packets */
    int ev = poll(fds, 1, -1);
    if (ev == -1) {
        ERROR("Poll failed");
        break;
    } else {
        write_packet(f, pkt_queue, &last_seqnum_written, &window_size, &min_seqnum_missing);
        if(!keep_receiving) break;
      /* Receiving data */
      char buf[MAX_PKT_SIZE];
      ssize_t read = recv(sfd, buf, MAX_PKT_SIZE, 0);
      if (read == -1) {
          ERROR("Error receiving");
          keep_receiving = 0;
          continue;
      }
      pkt_t *pkt = pkt_new();
      status = pkt_decode(buf, read, pkt);
      /* Ignore if the packet is corrupted XXX*/
      if (pkt_gen_crc1(pkt) != pkt_get_crc1(pkt))
          status = E_CRC;
      if (pkt_gen_crc2(pkt) != pkt_get_crc2(pkt))
          status = E_CRC;
      if (status != PKT_OK) {
        LOG("Packet received is corrupted");
        pkt_ready_for_queue = 0;
        pkt_del(pkt);
      }
      /* Check if the packet received is the terminal packet*/
      else if (pkt_get_length(pkt) == 0) {
         LOG("End packet received, seqnum : %d", pkt_get_seqnum(pkt));
         increment_seqnum(&min_seqnum_missing);
         keep_receiving = 0;
         pkt_ready_for_queue = 0;
         pkt_del(pkt);
      }
      /* Ignore if the packet is out of sequence */
      else if (seqnum_diff(last_seqnum_written, pkt_get_seqnum(pkt)) > MAX_WINDOW_SIZE
           || seqnum_diff(last_seqnum_written, pkt_get_seqnum(pkt)) <= 0)
     {
          LOG("The packet %d is out of sequence", pkt_get_seqnum(pkt));
          pkt_ready_for_queue = 0;
          pkt_del(pkt);
      }
      /* Check if the packet is truncated */
      else if (pkt_get_tr(pkt) == 1) {
        LOG("The packet %d is truncated, sending NACK...", pkt_get_seqnum(pkt));
        pkt_ready_for_queue = 0;
        last_timestamp = pkt_get_timestamp(pkt);
        tr = pkt_get_tr(pkt);
        pkt_del(pkt);
      } else {
        LOG("Packet %d correct ! Adding to queue", pkt_get_seqnum(pkt));
        pkt_ready_for_queue = 1;
      }
      /* Add to queue and decrement buffer if the packet is correct */
      if (pkt_ready_for_queue) {
          add_to_window(pkt_queue, pkt, &window_size, &min_seqnum_missing);
          last_timestamp = pkt_get_timestamp(pkt);
          tr = pkt_get_tr(pkt);
      }
      send_response(tr, min_seqnum_missing, window_size, last_timestamp, sfd);
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
