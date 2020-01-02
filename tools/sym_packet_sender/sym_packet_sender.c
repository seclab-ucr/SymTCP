

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <unistd.h>


#define MAX_PACKET_SIZE 4096
#define PACKET_SIZE 40
#define DEFAULT_TTL 128
#define DEFAULT_WINDOW_SIZE 29200

#define TCP_SYN (1 << 1)
#define TCP_ACK (1 << 4)
#define TCP_RST (1 << 2)
#define TCP_FIN 1
#define TCP_PSH (1 << 3)
#define TCP_URG (1 << 5)

/*
 * IP header
 */
struct myiphdr {
        u_int8_t    ihl:4,
                version:4;
        u_int8_t    tos;
        u_int16_t   tot_len;
        u_int16_t   id;
        u_int16_t   frag_off;
        u_int8_t    ttl;
        u_int8_t    protocol;
        u_int16_t   check;
        u_int32_t   saddr;
        u_int32_t   daddr;
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct mytcphdr {
        u_int16_t       th_sport;               /* source port */
        u_int16_t       th_dport;               /* destination port */
        u_int32_t       th_seq;                 /* sequence number */
        u_int32_t       th_ack;                 /* acknowledgement number */
    u_int8_t    th_x2:4,                /* (unused) */
            th_off:4;               /* data offset */
        u_int8_t    th_flags;
        u_int16_t   th_win;                 /* window */
        u_int16_t   th_sum;                 /* checksum */
        u_int16_t   th_urp;                 /* urgent pointer */
};

#define DEST "127.0.0.1"

int sport;

int raw_sock;

struct sockaddr_in dst_addr;

char packet[MAX_PACKET_SIZE];
int tot_len;

int init() {
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock == -1) {
        fprintf(stderr, "failed to create raw socket.\n");
        return -1;
    }
    int hdrincl = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1) {
        fprintf(stderr, "%s", strerror(errno));
        return -1;
    }

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(5555);
    inet_pton(AF_INET, DEST, (struct in_addr *)&dst_addr.sin_addr.s_addr);
    memset(dst_addr.sin_zero, 0, sizeof(dst_addr.sin_zero));

    srand(time(0));

    sport = (unsigned short)rand();

    // init the packet and reuse it everytime we call send_packet()
    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = 20; 

    iphdr->version = 4;
    iphdr->ihl = iphdr_len >> 2;
    iphdr->tos = 0;
    iphdr->id = htons((unsigned short)rand());
    iphdr->frag_off = 0x0040; // don't fragment
    iphdr->ttl = DEFAULT_TTL;
    iphdr->protocol = 6; // tcp
    // checksum will be filled automatically
    iphdr->saddr = 4223;
    iphdr->daddr = 4223;
    
    struct mytcphdr *tcphdr = (struct mytcphdr*)(packet + iphdr_len);
    int tcphdr_len = 20; 
    
    tcphdr->th_sport = htons(sport);
    tcphdr->th_dport = htons(5555);
    tcphdr->th_seq = htonl(1234567);
    tcphdr->th_ack = htonl(7654321);
    tcphdr->th_off = tcphdr_len >> 2;
    tcphdr->th_flags = TCP_SYN;
    tcphdr->th_win = htons(DEFAULT_WINDOW_SIZE);

    int payload_len = 0;
    char *payload = packet + iphdr_len + tcphdr_len;
    
    tot_len = iphdr_len + tcphdr_len + payload_len;

    return 0;
}

int send_packet() {
    int ret = sendto(raw_sock, packet, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    return ret;
}

int main()
{
    int i;
    int ret;

    ret = init();
    if (ret != 0) {
        fprintf(stderr, "init() failed.\n");
        return -1;
    }

    for (i = 0; ; ++i) {
        ret = send_packet();
        fprintf(stderr, "Sent packet #%d, size %d.\n", i, ret);
        usleep(100000);
    }
    return 0;
}
