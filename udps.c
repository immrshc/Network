#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 32768
#define MSGSIZE 1024
#define DEFAULT_PORT 5320

//ルーティングテーブルを表示させるコマンド
#define COMMAND_ROUTE "netstat -rn"

//ARPテーブルを表示させるコマンド
#define COMMAND_ARP "arp -an"

//TCPコネクションテーブルを表示させるコマンド
#define COMMAND_TCP "netstat -tn"

//NICの情報を表示させるコマンド
#define COMMAND_NIC "ifconfig -a"

enum {CMD_NAME, DST_PORT};

int execute(char *command, char *baf, int bufmax);

int main(int argc, char *argv[]){
    
    struct sockaddr_in server;
    struct sockaddr_in client;
    unsigned int len;
    //サーバのポート番号
    int port;
    //ソケットディスクリプタ
    int s;
    //受信したコマンドのワード数
    int cn;
    //送信メッセージのバイト数
    int sn;
    //受信メッセージのバイト数
    int rn;
    //ループ変数
    int i;
    char cmd1[BUFSIZE];
    char cmd2[BUFSIZE];
    char recv_buf[BUFSIZE];
    char send_buf[BUFSIZE];
    
    //引数の処理
    if (argc == 2){
        if ((port = atoi(argv[DST_PORT]) == 0)){
            struct servent *se;

            if ((se = getservbyname(argv[DST_PORT], "udp")) != NULL){
                port = (int) ntohs((u_int16_t) se->s_port);
            } else {
                fprintf(stderr, "getservbyname error\n");
                exit(EXIT_FAILURE);
            }
        }
    } else {
        port = DEFAULT_PORT;
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("socket");
        exit(EXIT_FAILURE);
    }

    //サーバのアドレスを設定する
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);
    if (bind(s, (struct sockaddr *) &server, sizeof server) < 0){
        perror("bind");
        exit(EXIT_FAILURE);
    }

    //サーバ処理メインルーチン
    while((rn = recvfrom(s, recv_buf, BUFSIZE - 1, 0,
                    (struct sockaddr *) &client, 
                    (len = sizeof client, &len))) >= 0){
        recv_buf[rn] = '\0';
        printf("receive from '%s'\n", inet_ntoa(client.sin_addr));
        printf("receive data '%s'\n", recv_buf);
        
        //受信コマンドの処理
        if ((cn = sscanf(recv_buf, "%s%s", cmd1, cmd2)) <= 0){
            sn = 0;
            printf("cn is lack of cmd\n");
        } else if (cn == 2 && strcmp(cmd1, "show") == 0) { 
            printf("cmd2 is %s.\n", cmd2);
            if (strcmp(cmd2, "route") == 0) {
                sn = execute(COMMAND_ROUTE, send_buf, BUFSIZE);
            } else if (strcmp(cmd2, "arp") == 0) {
                sn = execute(COMMAND_ARP, send_buf, BUFSIZE);
            } else if (strcmp(cmd2, "tcp") == 0) {
                sn = execute(COMMAND_TCP, send_buf, BUFSIZE);
            } else if (strcmp(cmd2, "nic") == 0) {
                sn = execute(COMMAND_NIC, send_buf, BUFSIZE);
            } else {
                sn = snprintf(send_buf, BUFSIZE, "parameter error '%s\n'"
                        "show [route|arp|tcp|nic]\n", cmd2);       
            }
        } else {
            if (strcmp(cmd1, "quit") == 0){
                break;
            }
            send_buf[0] = '\0';
            if (cn != 1 && strcmp(cmd1, "help") != 0){
                 snprintf(send_buf, BUFSIZE, "command error '%s\n'", cmd1);
            }
            strncat(send_buf, "Command:\n"
                              " show route\n"
                              " show arp\n"
                              " show tcp\n"
                              " show nic\n"
                              " quit\n"
                              " help\n", BUFSIZE - strlen(send_buf) - 1);
            sn = strlen(send_buf);
        }

        //メッセージ送信ループ
        for (i = 0; i <= sn; i += MSGSIZE) {
            //送信するメッセージのサイズ
            int size;

            if (sn -i > MSGSIZE) {
                size = MSGSIZE;
            } else if (sn - i <= 0) {
                size = 0;
            } else {
                size = sn - i;
            }
            
            if (sendto(s, &send_buf[i], size, 0, (struct sockaddr *) &client, len) < 0) {
                perror("sendto");
                exit(EXIT_FAILURE);
            }
        }
        printf("%s", send_buf);
    }

    close(s);
    return 0;

}

//コマンドを実行し、出力結果をバッファに格納する
int execute(char *command, char *buf, int bufmax){
    FILE *fp;
    int i;

    if((fp = popen(command, "r")) == NULL){
        perror(command);
       i = snprintf(buf, BUFSIZE, "server error: '%s' cannot execute.\n", command);
    } else {
        i = 0;
        while(i < bufmax - 1 && fscanf(fp, "%c", &buf[i]) == 1){
            i++;
        }
        buf[i] = '\0';
        pclose(fp);
    }
    return i;
}










