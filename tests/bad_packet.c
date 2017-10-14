
#include "common.h"

/**
* Test to create a packet and change his content to see error
*
*/


int main() {

	pkt_t   *pkt = pkt_new();
	memset(pkt, 0, sizeof(pkt_t));

	pkt_set_type(pkt, PTYPE_DATA);
	pkt_set_window(pkt, 1);
	pkt_set_payload(pkt, "test", sizeof("test"));
	pkt_set_crc(pkt, pkt_gen_crc(pkt));
	pkt_set_timestamp(pkt, 0);
	pkt_set_seqnum(pkt, 0);

	char    *encodebuf = malloc(MAX_PKT_SIZE);
	size_t  encodebuflen = MAX_PKT_SIZE;
	if(pkt_encode(pkt, encodebuf, &encodebuflen) != PKT_OK) {
		ERROR("erreur encode");
	}
	printf("%s\n", pkt->payload);
	char b = 'b';
	memset(encodebuf + offsetof(pkt_t, payload), b, sizeof(char));

	pkt_t 	*pktdecode = pkt_new();
	memset(pktdecode, 0, sizeof(pkt_t));

	char	*decodebuf = malloc(MAX_PKT_SIZE);
	size_t 	decodebuflen = MAX_PKT_SIZE;
	memset(decodebuf, 0, decodebuflen);

	if(pkt_decode(encodebuf, MAX_PKT_SIZE ,pktdecode) != PKT_OK) {
		return EXIT_SUCCESS;
	}
	
	return EXIT_FAILURE;
}