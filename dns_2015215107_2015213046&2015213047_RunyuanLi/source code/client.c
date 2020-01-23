#include "common.h"

int main(int argc, char* argv[]) {
    struct timeval boot;
    gettimeofday(&boot, NULL);
    srand(1000000 * boot.tv_sec + boot.tv_usec);
    struct timeval start, end;
    gettimeofday(&start, NULL);
    uint8_t buffer[BUF_SIZE];
    struct sockaddr_in dns_svr_addr;

    unsigned short dns_svr_port = 53;

    int sock;
    int nbytes;
    struct Message msg;

    if (argc < 4) {
        printf("client参数: %s 服务端IP 域名 类型 ...... \n", argv[0]);
        printf(
            "例如: %s 127.0.0.1 北邮.教育.中国 A 北邮.教育.中国 MX 教育.中国 "
            "CNAME ...\n",
            argv[0]);
        exit(1);
    }
    unsigned char* server_ip = argv[1];

    memset(&msg, 0, sizeof(struct Message));
    msg.id = rand() % 65535;
    msg.qr = 0;
    msg.aa = 0;
    msg.rd = 0;
    msg.ra = 0;
    msg.rcode = 0;

    msg.qdCount = 0;
    msg.anCount = 0;
    msg.nsCount = 0;
    msg.arCount = 0;
    int qCount;

    for (qCount = 2; qCount < argc; qCount += 2) {
        msg.qdCount++;
        struct Question* q;
        q = malloc(sizeof(struct Question));
        memset(q, 0, sizeof(struct Question));
        q->qName = decode_domain_name_from_byte(
            encode_domain_name_string(argv[qCount]));
        if (strcmp(argv[qCount + 1], "A") == 0) {
            q->qType = A_Resource_RecordType;
        } else if (strcmp(argv[qCount + 1], "NS") == 0) {
            q->qType = NS_Resource_RecordType;
        } else if (strcmp(argv[qCount + 1], "MX") == 0) {
            q->qType = MX_Resource_RecordType;
        } else if (strcmp(argv[qCount + 1], "CNAME") == 0) {
            q->qType = CNAME_Resource_RecordType;
        }

        q->qClass = IN_Class;
        q->next = msg.questions;
        msg.questions = q;
    }
    uint8_t* p = buffer;
    put16bits(&p, 0);
    if (encode_msg(&msg, &p) != 0) {
        printf("编组报文报错!\n");
        exit(1);
    }
    int buflen = p - buffer;
    uint8_t* p2 = buffer;
    put16bits(&p2, buflen - 2);

    memset(&dns_svr_addr, 0, sizeof(dns_svr_addr));
    dns_svr_addr.sin_family = AF_INET;
    dns_svr_addr.sin_addr.s_addr = inet_addr(server_ip);
    dns_svr_addr.sin_port = htons(dns_svr_port);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr*)&dns_svr_addr, sizeof(dns_svr_addr));
    if (send(sock, buffer, buflen, 0) != buflen) {
        printf("sendto() 发送了一个大小错误的内容.\n");
        close(sock);
        exit(1);
    }

    free_questions(msg.questions);
    free_resource_records(msg.answers);
    free_resource_records(msg.authorities);
    free_resource_records(msg.additionals);
    memset(&msg, 0, sizeof(struct Message));

    nbytes = recv(sock, buffer, sizeof(buffer), 0);
    p2 = buffer;
    get16bits(&p2);
    if (decode_msg(&msg, p2, nbytes) != 0) {
        printf("解析报文报错!\n");
        exit(1);
    }
    print_packet(&msg);
    gettimeofday(&end, NULL);
    int timeuse =
        1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    printf("时间: %d us\n", timeuse);

    close(sock);
    exit(0);
}
