#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CHKADDRESS(_saddr_) \
        {\
          unsigned char *p = (unsigned char *) &(_saddr_);\
          if ((p[0] == 127)\
           || (p[0] == 10)\
           || (p[0] == 172 && 16 <= p[1] && p[1] <= 31)\
           || (p[0] == 192 && p[1] == 168))\
            ;\
          else {\
            fprintf(stderr, "IP address error.\n");\
            exit(EXIT_FAILURE);\
          }\
        }

enum {CMD_NAME, DST_IP, START_PORT, LAST_PORT};
enum {CONNECT, NOCONNECT};

int tcpportscan(u_int32_t dst_ip, int dst_port);

int main(int argc, char *argv[]){
    u_int32_t dst_ip;
    int dst_port;
    int start_port;
    int end_port;

    if(argc != 4){
        fprintf(stderr, "usage: %s dst_ip start_port last_port\n", argv[CMD_NAME]);
        exit(EXIT_FAILURE);
    }

    dst_ip = inet_addr(argv[DST_IP]);
    start_port = atoi(argv[START_PORT]);
    end_port = atoi(argv[LAST_PORT]);
    //CHKADDRESS(dst_ip);

    for(dst_port = start_port; dst_port <= end_port; dst_port++){
        printf("Scan Port %d\r", dst_port);
        fflush(stdout);
        
        if(tcpportscan(dst_ip, dst_port) == NOCONNECT/*CONNECT*/){
            struct servent *se;

            se = getservbyport(htons(dst_port), "tcp");
            printf("%5d %-20s\n", dst_port, (se == NULL) ? "unknown": se->s_name);
        }
    }

    return 0;
}

int tcpportscan(u_int32_t dst_ip, int dst_port){
   struct sockaddr_in dest;
   int s;
   int ret;

   memset(&dest, 0, sizeof dest);
   dest.sin_family = AF_INET;
   dest.sin_port = htons(dst_port);
   dest.sin_addr.s_addr = dst_ip;

   if((s = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        exit(EXIT_FAILURE);
   }

   if(connect(s, (struct sockaddr *) &dest, sizeof dest) < 0){
        ret = NOCONNECT;
   }else{
        ret = CONNECT;
   }

   close(s);
   return ret;
}
