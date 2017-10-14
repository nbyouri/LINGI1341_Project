#include "common.h"

/**
 *
 * Packet handling functions.
 *
 */

pkt_t *
pkt_new()
{
    return calloc(1, sizeof(pkt_t));
}

void
pkt_del(pkt_t *pkt)
{
    if (pkt->payload != NULL) {
        free(pkt->payload);
        pkt->payload = NULL;
    }
    free(pkt);
    pkt = NULL;
}

pkt_status_code
pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    unsigned int read = 0;

    /* copy the header */
    memcpy(pkt, data, sizeof(pkt->header));
    read += sizeof(pkt->header);

    if (len < (sizeof(pkt_t) + pkt_get_length(pkt) - sizeof(pkt->payload))) {
        return E_NOMEM;
    }

    /* copy the payload and it's crc */
    if (!pkt_get_tr(pkt) && pkt_get_length(pkt) > 0) {
        pkt_set_payload(pkt, data + read, pkt_get_length(pkt));
        read += pkt_get_length(pkt);
        memcpy(&(pkt->crc2), data + read, sizeof(uint32_t));
        read += sizeof(pkt->crc2);
    }

    /* verify the header crc */
    if (pkt_gen_crc1(pkt) != pkt_get_crc1(pkt)) {
        return E_CRC;
    }

    /* verify the payload crc */
    if (!pkt_get_tr(pkt)) {
        if (pkt_gen_crc2(pkt) != pkt_gen_crc2(pkt)) {
            return E_CRC;
        }
    }


    return PKT_OK;
}

pkt_status_code
pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    /* payload length */
    uint16_t plen = pkt_get_length(pkt);

    if (*len < sizeof(pkt_t) + plen - sizeof(char *)) {
        return E_NOMEM;
    }

    /* encode the header */
    *len = sizeof(pkt->header) - sizeof(uint32_t);
    memcpy(buf, pkt, *len);

    /* encode the crc1 */
    const uint32_t crc1 = pkt_gen_crc1(pkt);
    memcpy(buf + *len, &crc1, sizeof(crc1));
    *len += sizeof(crc1);
    pkt_set_crc1((pkt_t *)pkt, crc1);

    /* copy the payload */
    if (plen > 0) {
        memcpy(buf + *len, pkt->payload, plen);
        *len += plen;
    }

    /* copy the crc2 */
    const uint32_t crc2 = pkt_gen_crc2(pkt);
    memcpy(buf + *len, &crc2, sizeof(crc2));
    *len += sizeof(crc2);

    return PKT_OK;
}

ptypes_t
pkt_get_type(const pkt_t *pkt)
{
    return pkt->header.type;
}

uint8_t
pkt_get_tr(const pkt_t *pkt)
{
    return pkt->header.tr;
}

uint8_t
pkt_get_window(const pkt_t *pkt)
{
    return pkt->header.window;
}

uint8_t
pkt_get_seqnum(const pkt_t *pkt)
{
    return pkt->header.seqnum;
}

uint16_t
pkt_get_length(const pkt_t *pkt)
{
    return ntohs(pkt->header.length);
}

uint32_t
pkt_get_timestamp(const pkt_t *pkt)
{
    return pkt->header.timestamp;
}

uint32_t
pkt_get_crc1(const pkt_t *pkt)
{
    return pkt->header.crc1;
}

uint32_t
pkt_get_crc2(const pkt_t *pkt)
{
    return pkt->crc2;
}

uint32_t
pkt_gen_crc1(const pkt_t *pkt)
{
    int tr = pkt_get_tr(pkt);
    pkt_set_tr((pkt_t *)pkt, 0);
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (Bytef *)pkt, sizeof(pkt->header) - sizeof(uint32_t));
    pkt_set_tr((pkt_t *)pkt, tr);
    return htonl((uint32_t)crc);
}

uint32_t
pkt_gen_crc2(const pkt_t *pkt)
{
     uLong crc = crc32(0L, Z_NULL, 0);
     crc = crc32(crc, (Bytef *)pkt->payload, pkt_get_length(pkt));
     return htonl((uint32_t)crc);
}

const char *
pkt_get_payload(const pkt_t *pkt)
{
    if (pkt->payload == NULL) {
        return NULL;
    }
    return pkt->payload;
}


pkt_status_code
pkt_set_type(pkt_t *pkt, const ptypes_t type)
{
    if (type != PTYPE_DATA && type != PTYPE_ACK && type != PTYPE_NACK) {
        return E_TYPE;
    } else {
        pkt->header.type = type;
        return PKT_OK;
    }
}

pkt_status_code
pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    if (tr > 1) {
        return E_TR;
    } else {
        pkt->header.tr = tr;
        return PKT_OK;
    }
}

pkt_status_code
pkt_set_window(pkt_t *pkt, const uint8_t window)
{
    if (window > MAX_WINDOW_SIZE) {
        return E_WINDOW;
    } else {
        pkt->header.window = window;
        return PKT_OK;
    }
}

pkt_status_code
pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    pkt->header.seqnum = seqnum;
    return PKT_OK;
}

pkt_status_code
pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    if (length > MAX_PAYLOAD_SIZE) {
        return E_LENGTH;
    } else {
        pkt->header.length = htons(length);
        return PKT_OK;
    }
}

pkt_status_code
pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    pkt->header.timestamp = timestamp;
    return PKT_OK;
}

pkt_status_code
pkt_set_crc1(pkt_t *pkt, const uint32_t crc)
{
    pkt->header.crc1 = crc;
    return PKT_OK;
}

pkt_status_code
pkt_set_crc2(pkt_t *pkt, const uint32_t crc)
{
    pkt->crc2 = crc;
    return PKT_OK;
}

pkt_status_code
pkt_set_payload(pkt_t *pkt, const char *data, const uint16_t length)
{
    /* null payload has a length of 0, usually for session termination */
    if (data == NULL) {
        pkt_set_length(pkt, 0);
        pkt->payload = NULL;
        return PKT_OK;
    }

    pkt->payload = malloc(length);
    if (pkt->payload == NULL) {
        return E_NOMEM;
    }

    memcpy(pkt->payload, data, length);

    pkt_status_code ret = pkt_set_length(pkt, length);
    if (ret != PKT_OK) {
        return ret;
    }

    return PKT_OK;
}

void
pkt_to_string(const pkt_t *pkt)
{
    LOG("----- packet -----\n"
        "header { \n"
        "  type   = %d\n"
        "  window = %d\n"
        "  seqnum = %d\n"
        "  length = %d\n"
        "  timestamp = %d\n"
        "  crc1 = %d\n"
        "}\n"
        "payload = %s\n"
        "crc2 = %d\n",
        pkt_get_type(pkt),
        pkt_get_window(pkt),
        pkt_get_seqnum(pkt),
        pkt_get_length(pkt),
        pkt_get_timestamp(pkt),
        pkt_get_crc1(pkt),
        pkt_get_payload(pkt) == NULL ? "[null]" : pkt_get_payload(pkt),
        pkt_get_crc2(pkt));
}

/*
 *
 * Find how many packets to decode are in a buffer.
 *
 */
size_t
nb_pkt_in_buffer(const ssize_t bytes)
{
    unsigned int nb_packets = 0;
    unsigned int payload_space = (bytes / MAX_PAYLOAD_SIZE);

    if (payload_space == 0) {
        nb_packets = 1;
    } else {
        nb_packets = payload_space;

        if ((bytes % MAX_PAYLOAD_SIZE) > 0) {
            nb_packets++;
        }
    }
    return nb_packets;
}
