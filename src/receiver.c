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

    /* XXX RECEIVE THE DATA TO IMPLEMENT XXX */

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
