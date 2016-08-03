#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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

#define BUFSIZE    4096
#define PACKET_LEN 72

enum {CMD_NAME, START_IP, LAST_IP};

void make_icmp8_packet(struct icmp *icmp, int len, int n);
void tvsub(struct timeval *out, struct timeval *in);
u_int16_t checksum(u_int16_t *data, int len);

int main(int argc, char *argv[]){
    struct sockaddr_in send_sa;
    int s;
    char send_buff[PACKET_LEN];
    char recv_buff[BUFSIZE];
    int start_ip;
    int end_ip;
    int dst_ip;
    int on = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s start_ip last_ip\n", argv[CMD_NAME]);
        exit(EXIT_FAILURE);
    }

    //IPアドレスの範囲を設定する
    start_ip = ntohl(inet_addr(argv[START_IP]));
    end_ip = ntohl(inet_addr(argv[LAST_IP]));

    memset(&send_sa, 0, sizeof send_sa);
    send_sa.sin_family = AF_INET;

    //ICMP送信用のrawソケットのオープン
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
        perror("socket(SOCK_RAW, IPPROTO_ICMP)");
        exit(EXIT_FAILURE);
    }

    //スキャンホストメインルーチン
    for(dst_ip = start_ip; dst_ip <= end_ip; dst_ip++){
        int i;
        send_sa.sin_addr.s_addr = htonl(dst_ip);
        CHKADDRESS(send_sa.sin_addr);

        for(i = 0; i < 3; i++){
            struct timeval tv;
            printf("scan %s (%d)\r", inet_ntoa(send_sa.sin_addr), i + 1);
            fflush(stdout);

            //ICMPエコー要求パケットを作成して送信する
            make_icmp8_packet((struct icmp *) send_buff, PACKET_LEN, i);
            if (sendto(s, (char *) &send_buff, PACKET_LEN, 0,
                        (struct sockaddr *) &send_sa, sizeof send_sa) < 0) {
                perror("sendto");
                exit(EXIT_FAILURE);
            }

            //selectのタイムアウトの設定
            tv.tv_sec = 0;
            tv.tv_usec = 200 * 1000;

            while(1){
                fd_set readfd;
                struct ip *ip;
                int ihlen;

                //selectでパケットの到着を待つ
                FD_ZERO(&readfd);
                FD_SET(s, &readfd);
                
                if(select(s + 1, &readfd, NULL, NULL, &tv) <= 0){
                    break;
                }
                
                if(recvfrom(s, recv_buff, BUFSIZE, 0, NULL, NULL) < 0){
                    perror("recvfrom");
                    exit(EXIT_FAILURE);
                }

                ip = (struct ip *) recv_buff;
                ihlen = ip->ip_hl << 2;
                if(ip->ip_src.s_addr == send_sa.sin_addr.s_addr){
                    struct icmp *icmp;

                    icmp = (struct icmp *) (recv_buff + ihlen);
                    if(icmp->icmp_type == ICMP_ECHOREPLY){
                        printf("%-15s", inet_ntoa(*(struct in_addr *) &(ip->ip_src.s_addr)));
                        gettimeofday(&tv, (struct timezone *) 0);
                        tvsub(&tv, (struct timeval *) (icmp->icmp_data));
                        printf(": RTT = %6.4f ms\n", tv.tv_sec*1000.0 + tv.tv_usec/1000.0);
                        goto exit_loop;
                    }
                }
            }
        }   
 exit_loop:;
    }
    close(s);
    return 0;
}

//ICMPパケットの作成
void make_icmp8_packet(struct icmp *icmp, int len, int n){
    memset(icmp, 0, len);
    //時刻情報をデータ部に記録
    gettimeofday((struct timeval *) (icmp->icmp_data), (struct timezone *) 0);
    //ICMPヘッダの作成
    icmp->icmp_code = 0;
    icmp->icmp_id = 0;
    icmp->icmp_seq = n;
    //チェックサムの計算
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((u_int16_t *) icmp, len);
}

//struct timevalの引数で、結果をoutに格納する
void tvsub(struct timeval *out, struct timeval *in){
    if ((out->tv_usec -= in->tv_usec) < 0){
        out->tv_sec--;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

//チェックサムの計算
u_int16_t checksum(u_int16_t *data, int len){
    u_int32_t sum = 0;

    for(; len > 1; len -= 2){
        sum += *data++;
        if(sum & 0x80000000){
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    if(len == 1){
        u_int16_t i = 0;
        *(u_char*) (&i) = *(u_char *) data;
        sum += i;
    }

    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

