#include "common.h"

struct DomainName *get_reply_domain(struct DomainName *, struct DomainName *);

unsigned char *get_data(unsigned char **, unsigned char);

int read_file(struct ResourceRecord *, struct DomainName *, unsigned char *);

int save_cache(struct ResourceRecord *, struct DomainName *, unsigned char *,
               int, int);

int push_query(struct Message *);

void send_query(struct Message *, unsigned char *, struct DomainName *, int);

void delete_query();

void client_process(struct DomainName *, struct ResourceRecord *);

void resolve(struct Message *, boolean);

void resolve_recursive(struct Message *);

struct Question *Queries;

unsigned char *cacheFileName;
unsigned char *resolveFileName;
unsigned char *nsFileName;
unsigned char *bindIpAddr;
boolean isLocal;
boolean recursiveAvailable;

int main(int argc, char *argv[]) {
    uint8_t buffer[BUF_SIZE];
    uint8_t *p;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int nbytes, rc, listen_rc, sock, sock_2, port = PORT_NUM;
    struct Message msg;
    memset(&msg, 0, sizeof(struct Message));

    if (argc != 7) {
        printf(
            "server参数: %s 本机IP 解析文件名 缓存文件名 已知权威服务器文件名 "
            "是否是localserver 是否递归 \n",
            argv[0]);
        exit(1);
    }
    bindIpAddr = argv[1];
    resolveFileName = argv[2];
    cacheFileName = argv[3];
    nsFileName = argv[4];
    isLocal = atoi(argv[5]);
    recursiveAvailable = atoi(argv[6]);
    if (isLocal) recursiveAvailable = TRUE;

    memset(&msg, 0, sizeof(struct Message));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(bindIpAddr);
    addr.sin_port = htons(port);
    if (isLocal) {
        sock = socket(PF_INET, SOCK_STREAM, 0);
        rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        listen_rc = listen(sock, 10);
        if (rc != 0 || listen_rc < 0) {
            printf("TCP的socket绑定失败: %s\n", strerror(errno));
            exit(1);
        }

    } else {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        rc = bind(sock, (struct sockaddr *)&addr, addr_len);
        if (rc != 0) {
            printf("UDP的socket绑定失败: %s\n", strerror(errno));
            exit(1);
        }
    }
    printf("监听地址: %s  端口号: 53\n", bindIpAddr);

    while (TRUE) {
        free_questions(msg.questions);
        free_resource_records(msg.answers);
        free_resource_records(msg.authorities);
        free_resource_records(msg.additionals);
        memset(&msg, 0, sizeof(struct Message));
        memset(&buffer, 0, sizeof(buffer));

        if (isLocal) {
            sock_2 = accept(sock, (struct sockaddr *)&client_addr, &addr_len);
            nbytes = recv(sock_2, buffer, sizeof(buffer), 0);
            p = buffer;
            get16bits(&p);
            nbytes -= 2;
        } else {
            nbytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&client_addr, &addr_len);
            p = buffer;
        }

        if (decode_msg(&msg, p, nbytes) != 0) {
            continue;
        }
        struct timeval start, end;
        gettimeofday(&start, NULL);
        srand(start.tv_usec);
        print_packet(&msg);

        push_query(&msg);
        msg.qr = 1;
        msg.aa = 1;
        msg.rd = 0;
        msg.ra = 0;
        msg.rcode = Ok_ResponseType;
        msg.anCount = 0;
        msg.nsCount = 0;
        msg.arCount = 0;
        while (Queries != NULL) {
            if (recursiveAvailable) {
                resolve_recursive(&msg);
            } else {
                resolve(&msg, FALSE);
            }
        }

        print_packet(&msg);

        memset(&buffer, 0, sizeof(buffer));

        p = buffer;
        if (isLocal) {
            put16bits(&p, 0);
        }
        if (encode_msg(&msg, &p) != 0) {
            continue;
        }
        int buflen = p - buffer;
        if (isLocal) {
            p = buffer;
            put16bits(&p, buflen - 2);
            send(sock_2, buffer, buflen, 0);
            close(sock_2);
        } else {
            sendto(sock, buffer, buflen, 0, (struct sockaddr *)&client_addr,
                   addr_len);
        }
        gettimeofday(&end, NULL);
        int timeuse =
            1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
        printf("解析时间: %d us\n", timeuse);
    }
}

void resolve(struct Message *msg, boolean find_authority_server) {
    int rc;
    struct ResourceRecord *rr;
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));
    rr->name = get_reply_domain(Queries->qName, NULL);
    rr->type = Queries->qType;
    rr->class = Queries->qClass;

    switch (rr->type) {
        case A_Resource_RecordType:
        case MX_Resource_RecordType:
        case CNAME_Resource_RecordType:
            if (find_authority_server) {
                rc = read_file(rr, rr->name, nsFileName);
            } else {
                rc = read_file(rr, rr->name, resolveFileName);
                if (rc != 2) {
                    free(rr->name);
                    free(rr);
                    rr = malloc(sizeof(struct ResourceRecord));
                    memset(rr, 0, sizeof(struct ResourceRecord));
                    rr->name = get_reply_domain(Queries->qName, NULL);
                    rr->type = Queries->qType;
                    rr->class = Queries->qClass;
                    rc = read_file(rr, rr->name, cacheFileName);
                }
            }
            break;

        default:
            msg->rcode = NotImplemented_ResponseType;
            printf("该类型的查询无答案 %d.\n", rr->type);
            rc = -1;
    }

    if (find_authority_server) {
        if (rc < 0) {
            free(rr->name);
            free(rr);
            struct Question *next;
            next = Queries->next;
            free_domain_name(Queries->qName);
            free(Queries);
            Queries = next;
        } else {
            struct Question *next;
            next = Queries->next;
            free_domain_name(Queries->qName);
            free(Queries);
            Queries = next;
            msg->nsCount++;
            rr->next = msg->authorities;
            msg->authorities = rr;
        }
    } else {
        if (rc == 2) {
            struct Question *next;
            next = Queries->next;
            free_domain_name(Queries->qName);
            free(Queries);
            Queries = next;

            msg->anCount++;
            rr->next = msg->answers;
            msg->answers = rr;

            if (rr->type == MX_Resource_RecordType) {
                struct ResourceRecord *rr_mx;
                rr_mx = malloc(sizeof(struct ResourceRecord));
                memset(rr_mx, 0, sizeof(struct ResourceRecord));
                rr_mx->name = decode_domain_name_from_byte(
                    rr->rd_data.mx_record.exchange);
                rr_mx->type = A_Resource_RecordType;
                rr_mx->class = rr->class;
                rc = read_file(rr_mx, rr_mx->name, resolveFileName);
                if (rc != 2) {
                    free(rr_mx->name);
                    free(rr_mx);
                    rr_mx = malloc(sizeof(struct ResourceRecord));
                    memset(rr_mx, 0, sizeof(struct ResourceRecord));
                    rr_mx->name = decode_domain_name_from_byte(
                        rr->rd_data.mx_record.exchange);
                    rr_mx->type = A_Resource_RecordType;
                    rr_mx->class = rr->class;
                    rc = read_file(rr_mx, rr_mx->name, cacheFileName);
                }

                if (rc > 0) {
                    msg->arCount++;
                    rr_mx->next = msg->additionals;
                    msg->additionals = rr_mx;
                } else {
                    free(rr_mx->name);
                    free(rr_mx);
                }
            }
        } else {
            Queries->qType = A_Resource_RecordType;
            resolve(msg, TRUE);
        }
    }
}

void resolve_recursive(struct Message *msg) {
    int rc;
    struct ResourceRecord *rr;
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));
    rr->name = get_reply_domain(Queries->qName, NULL);
    rr->type = Queries->qType;
    rr->class = Queries->qClass;

    switch (rr->type) {
        case A_Resource_RecordType:
        case MX_Resource_RecordType:
        case CNAME_Resource_RecordType:
            rc = read_file(rr, rr->name, resolveFileName);
            if (rc != 2) {
                free(rr->name);
                free(rr);
                rr = malloc(sizeof(struct ResourceRecord));
                memset(rr, 0, sizeof(struct ResourceRecord));
                rr->name = get_reply_domain(Queries->qName, NULL);
                rr->type = Queries->qType;
                rr->class = Queries->qClass;
                rc = read_file(rr, rr->name, cacheFileName);
            }
            break;

        default:
            free(rr->name);
            free(rr);
            msg->rcode = NotImplemented_ResponseType;
            printf("该类型的查询无答案 %d.\n", rr->type);
            struct Question *next;
            next = Queries->next;
            free_domain_name(Queries->qName);
            free(Queries);
            Queries = next;
            return;
    }

    if (rc == 2) {
        struct Question *next;
        next = Queries->next;
        free_domain_name(Queries->qName);
        free(Queries);
        Queries = next;

        msg->anCount++;
        rr->next = msg->answers;
        msg->answers = rr;

        if (rr->type == MX_Resource_RecordType) {
            struct ResourceRecord *rr_mx;
            rr_mx = malloc(sizeof(struct ResourceRecord));
            memset(rr_mx, 0, sizeof(struct ResourceRecord));
            rr_mx->name =
                decode_domain_name_from_byte(rr->rd_data.mx_record.exchange);
            rr_mx->type = A_Resource_RecordType;
            rr_mx->class = rr->class;
            rc = read_file(rr_mx, rr_mx->name, resolveFileName);
            if (rc != 2) {
                free(rr_mx->name);
                free(rr_mx);
                rr_mx = malloc(sizeof(struct ResourceRecord));
                memset(rr_mx, 0, sizeof(struct ResourceRecord));
                rr_mx->name = decode_domain_name_from_byte(
                    rr->rd_data.mx_record.exchange);
                rr_mx->type = A_Resource_RecordType;
                rr_mx->class = rr->class;
                rc = read_file(rr_mx, rr_mx->name, cacheFileName);
            }

            if (rc > 0) {
                msg->arCount++;
                rr_mx->next = msg->additionals;
                msg->additionals = rr_mx;
            } else {
                free(rr_mx->name);
                free(rr_mx);
            }
        }
    } else {
        client_process(get_reply_domain(Queries->qName, NULL), rr);
        free(rr->name);
        free(rr);
    }
}

void client_process(struct DomainName *query_domain,
                    struct ResourceRecord *rr) {
    int rc, query_type;
    query_type = rr->type;
    rr->type = A_Resource_RecordType;
    rc = read_file(rr, query_domain, nsFileName);
    if (isLocal && rc < 0) {
        query_domain =
            decode_domain_name_from_byte(encode_domain_name_string("根.我"));
        rc = read_file(rr, query_domain, nsFileName);
    }
    rr->type = query_type;
    if (rc > 0) {
        unsigned char *addr = rr->rd_data.a_record.addr;
        while (TRUE) {
            unsigned char *ipStr;
            ipStr = malloc(sizeof(unsigned char) * 16);
            memset(ipStr, 0, sizeof(unsigned char) * 16);
            sprintf(ipStr, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
            struct Message *msg;
            msg = malloc(sizeof(struct Message));
            memset(msg, 0, sizeof(struct Message));
            send_query(msg, ipStr, Queries->qName, rr->type);
            int has_result = 0;
            has_result += save_cache(msg->answers, Queries->qName,
                                     cacheFileName, rr->type, 0);
            has_result += save_cache(msg->additionals, Queries->qName,
                                     cacheFileName, rr->type, 1);
            if (has_result > 0) {
                break;
            } else {
                if (msg->nsCount > 0) {
                    if (msg->authorities->type == A_Resource_RecordType) {
                        addr = msg->authorities->rd_data.a_record.addr;
                        continue;
                    }
                }
                delete_query();
                msg->rcode = Refused_ResponseType;
                return;
            }
        }
    } else {
        delete_query();
        return;
    }
}

void send_query(struct Message *msg, unsigned char *remote_ip,
                struct DomainName *query_domain, int query_type) {
    struct timeval start, end;
    uint8_t buffer[BUF_SIZE];
    struct sockaddr_in next_svr;
    unsigned short port = 53;
    struct sockaddr_in client_addr;
    struct sockaddr_in from_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int sock;
    int nbytes;

    memset(&next_svr, 0, sizeof(next_svr)); /*Zero out structure*/
    next_svr.sin_family = AF_INET;
    next_svr.sin_addr.s_addr = inet_addr(remote_ip);
    next_svr.sin_port = htons(port);

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in clt_addr;
    memset(&clt_addr, 0, sizeof(clt_addr));
    clt_addr.sin_family = AF_INET;
    clt_addr.sin_addr.s_addr = inet_addr(bindIpAddr);
    bind(sock, (struct sockaddr *)&clt_addr, sizeof(clt_addr));

    memset(msg, 0, sizeof(struct Message));
    memset(&buffer, 0, sizeof(buffer));

    msg->id = rand() % 65535;
    msg->qr = 0;
    msg->aa = 0;
    msg->rd = 0;
    msg->ra = 0;
    msg->rcode = 0;

    msg->qdCount = 0;
    msg->anCount = 0;
    msg->nsCount = 0;
    msg->arCount = 0;

    struct Question *q;
    q = malloc(sizeof(struct Question));
    memset(q, 0, sizeof(struct Question));
    q->qName = get_reply_domain(query_domain, NULL);
    q->qType = query_type;
    q->qClass = IN_Class;
    q->next = msg->questions;
    msg->questions = q;

    msg->qdCount++;

    uint8_t *p = buffer;
    if (encode_msg(msg, &p) != 0) {
        printf("编组报文报错!\n");
        exit(1);
    }
    int buflen = p - buffer;

    gettimeofday(&start, NULL);

    if ((sendto(sock, buffer, buflen, 0, (struct sockaddr *)&next_svr,
                sizeof(next_svr))) != buflen)
        printf("sendto() 发送了一个大小错误的内容.\n");

    free_questions(msg->questions);
    free_resource_records(msg->answers);
    free_resource_records(msg->authorities);
    free_resource_records(msg->additionals);
    memset(msg, 0, sizeof(struct Message));
    memset(buffer, 0, sizeof(buffer));
    nbytes = recvfrom(sock, buffer, sizeof(buffer), 0,
                      (struct sockaddr *)&client_addr, &addr_len);
    if (decode_msg(msg, buffer, nbytes) != 0) {
        printf("解析报文报错\n");
        exit(1);
    }
    printf("响应来自于 %s:\n", remote_ip);
    print_packet(msg);
    gettimeofday(&end, NULL);
    int timeuse =
        1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    printf("解析时间: %d us\n", timeuse);
    close(sock);
}

int read_file(struct ResourceRecord *rr, struct DomainName *targetDomainName,
              unsigned char *fileName) {
    FILE *fd = fopen(fileName, "r");
    boolean has_best_match = FALSE;
    boolean got_target = FALSE;
    int best_match_count = 0;
    unsigned char *pos;
    unsigned char *buf;
    buf = malloc(sizeof(unsigned char) * 1024);
    memset(buf, 0, sizeof(unsigned char) * 1024);
    int bufsize = 1024;
    unsigned char *type, *class;
    switch (rr->type) {
        case A_Resource_RecordType:
            type = "A";
            break;
        case CNAME_Resource_RecordType:
            type = "CNAME";
            break;
        case MX_Resource_RecordType:
            type = "MX";
            break;
        default:
            type = "A";
    }
    switch (rr->class) {
        case IN_Class:
            class = "IN";
            break;
        default:
            class = "IN";
    }
    while (fgets(buf, bufsize, fd) > 0) {
        unsigned char *buf_head = buf;
        if (strlen(buf) <= 1) continue;
        if (strcmp(class, get_data(&buf, ',')) != 0) continue;
        if (strcmp(type, get_data(&buf, ',')) != 0) continue;
        struct DomainName *domainNamePos = targetDomainName;
        int match_count = 0;
        boolean line_domain_reach_end = FALSE;
        struct DomainName *domainName_new;
        struct DomainName *domainName_new_head;
        unsigned char *pos;
        unsigned char *edge_pos;
        unsigned char *buf_domain;
        int len = 0, position_point = 0, first_get = 1, count = 0;

        edge_pos = strchr(buf, ',');
        len = edge_pos - buf;
        count = len;
        buf_domain = malloc(sizeof(unsigned char) * (len + 1));
        memset(buf_domain, 0, sizeof(unsigned char) * (len + 1));
        memcpy(buf_domain, buf, len);
        domainName_new =
            decode_domain_name_from_byte(encode_domain_name_string(buf_domain));
        domainName_new_head = domainName_new;
        buf += count + 1;
        while (TRUE) {
            if (domainName_new == NULL || domainNamePos == NULL) break;
            if (domainName_new->next == NULL) {
                line_domain_reach_end = TRUE;
            }
            int compareResult =
                strcmp(domainNamePos->domain, domainName_new->domain);

            if (compareResult != 0) {
                break;
            }
            match_count += 1;
            if (line_domain_reach_end) {
                if (match_count > best_match_count) {
                    if (domainNamePos->next == NULL) {
                        got_target = TRUE;
                    }
                    rr->name = domainName_new_head;
                    best_match_count = match_count;
                    has_best_match = TRUE;
                    if (rr->type == A_Resource_RecordType) {
                        unsigned char *addr = rr->rd_data.a_record.addr;
                        unsigned char *ipAddr = get_data(&buf, ',');
                        rr->ttl = 86400;
                        rr->rd_length = 4;
                        addr[0] = atoi(get_data(&ipAddr, '.'));
                        addr[1] = atoi(get_data(&ipAddr, '.'));
                        addr[2] = atoi(get_data(&ipAddr, '.'));
                        addr[3] = atoi(get_data(&ipAddr, '\0'));
                    } else if (rr->type == CNAME_Resource_RecordType) {
                        unsigned char *cname_name = get_data(&buf, ',');
                        rr->ttl = atol(get_data(&buf, '\n'));
                        rr->rd_data.cname_record.name =
                            encode_domain_name_string(cname_name);
                        rr->rd_length =
                            strlen(rr->rd_data.cname_record.name) + 1;
                    } else if (rr->type == MX_Resource_RecordType) {
                        unsigned char *mxname_name = get_data(&buf, ',');
                        unsigned char *buf_mx = mxname_name;
                        unsigned char *pos_mx;
                        int len_mx = 0;

                        pos_mx = strchr(buf_mx, '#');
                        len_mx = pos_mx - buf_mx;
                        mxname_name = malloc(len_mx + sizeof(unsigned char));
                        memset(mxname_name, 0, len_mx + sizeof(unsigned char));
                        memcpy(mxname_name, buf_mx, len_mx);
                        mxname_name[len_mx] = '\0';

                        buf_mx += len_mx + 1;
                        rr->rd_data.mx_record.preference = atoi(buf_mx);

                        rr->ttl = atol(get_data(&buf, '\n'));
                        rr->rd_data.mx_record.exchange =
                            encode_domain_name_string(mxname_name);
                        rr->rd_length =
                            strlen(rr->rd_data.mx_record.exchange) + 1 + 2;
                    }
                }
                break;
            }
            domainNamePos = domainNamePos->next;
            domainName_new = domainName_new->next;
        }
        buf = buf_head;
    }
    fclose(fd);
    if (got_target) return 2;
    if (has_best_match) return 1;
    return -1;
}

int save_cache(struct ResourceRecord *rr, struct DomainName *query_domain,
               unsigned char *fileName, int query_type, int force_save) {
    unsigned char *type;
    unsigned char *class;
    unsigned char *buf;
    unsigned char *result_line;
    unsigned char *search_keyword;
    buf = malloc(sizeof(unsigned char) * 1024);
    memset(buf, 0, sizeof(unsigned char) * 1024);
    result_line = malloc(sizeof(unsigned char) * 1024);
    memset(result_line, 0, sizeof(unsigned char) * 1024);
    search_keyword = malloc(sizeof(unsigned char) * 1024);
    memset(search_keyword, 0, sizeof(unsigned char) * 1024);
    int bufsize = 1024;
    boolean has_task = FALSE;
    FILE *fd = fopen(fileName, "r+");
    while (rr) {
        if ((strcmp(decode_domain_name_byte(structure_to_bytes(rr->name)),
                    decode_domain_name_byte(
                        structure_to_bytes(query_domain))) == 0 &&
             query_type == rr->type) ||
            force_save == 1) {
            has_task = TRUE;
            switch (rr->type) {
                case A_Resource_RecordType:
                    type = "A";
                    break;
                case CNAME_Resource_RecordType:
                    type = "CNAME";
                    break;
                case MX_Resource_RecordType:
                    type = "MX";
                    break;
                default:
                    type = "A";
            }
            switch (rr->class) {
                case IN_Class:
                    class = "IN";
                    break;
                default:
                    class = "IN";
            }

            unsigned char *rr_result;
            rr_result = malloc(sizeof(unsigned char) * 1024);
            memset(rr_result, 0, sizeof(unsigned char) * 1024);

            switch (rr->type) {
                case A_Resource_RecordType:
                    sprintf(rr_result, "%u.%u.%u.%u",
                            rr->rd_data.a_record.addr[0],
                            rr->rd_data.a_record.addr[1],
                            rr->rd_data.a_record.addr[2],
                            rr->rd_data.a_record.addr[3]);
                    break;
                case CNAME_Resource_RecordType:
                    sprintf(
                        rr_result, "%s",
                        decode_domain_name_byte(rr->rd_data.cname_record.name));
                    break;
                case MX_Resource_RecordType:
                    sprintf(
                        rr_result, "%s#%u",
                        decode_domain_name_byte(rr->rd_data.mx_record.exchange),
                        rr->rd_data.mx_record.preference);
                    break;
                default:
                    printf("Unknown Resource Record { ??? }");
            }
            sprintf(result_line, "%s,%s,%s,%s,%d\n", class, type,
                    decode_domain_name_byte(structure_to_bytes(rr->name)),
                    rr_result, rr->ttl);
            sprintf(search_keyword, "%s,%s,%s", class, type,
                    decode_domain_name_byte(structure_to_bytes(rr->name)));

            boolean found_flag = FALSE;
            while (fgets(buf, bufsize, fd) > 0) {
                unsigned char *orig_buf_pos = buf;
                if (strlen(buf) < 5) {
                    memset(buf, 0, sizeof(unsigned char) * 1024);
                    continue;
                }
                if (strstr(buf, search_keyword) != 0) {
                    found_flag = TRUE;
                    break;
                }
                buf = orig_buf_pos;
                memset(buf, 0, sizeof(unsigned char) * 1024);
            }
            if (found_flag == FALSE) {
                fputs(result_line, fd);
            }
        }
        rewind(fd);
        rr = rr->next;
    }
    fclose(fd);
    return has_task;
}

unsigned char *get_data(unsigned char **buffer, unsigned char divider) {
    unsigned char *buf = *buffer;
    unsigned char *pos = strchr(buf, divider);
    if (pos == NULL) {
        return 0;
    }
    unsigned char *temp;
    temp = malloc(pos - buf + sizeof(unsigned char));
    memset(temp, 0, pos - buf + sizeof(unsigned char));
    memcpy(temp, buf, pos - buf);
    temp[pos - buf] = '\0';
    *buffer += pos - buf + 1;
    return temp;
}

struct DomainName *get_reply_domain(struct DomainName *domain,
                                    struct DomainName *last_domain_point) {
    struct DomainName *new_domain_name, *target_pointer = domain;
    new_domain_name = malloc(sizeof(struct DomainName));
    memset(new_domain_name, 0, sizeof(struct DomainName));
    struct DomainName *head = new_domain_name;
    boolean first = TRUE;
    while (target_pointer->next != last_domain_point) {
        if (!first) {
            new_domain_name->next = malloc(sizeof(struct DomainName));
            memset(new_domain_name->next, 0, sizeof(struct DomainName));
            new_domain_name = new_domain_name->next;
            target_pointer = target_pointer->next;
        }
        unsigned char *name_str;
        name_str = malloc(sizeof(unsigned char) * (target_pointer->length + 1));
        memset(name_str, 0,
               sizeof(unsigned char) * (target_pointer->length + 1));
        memcpy(name_str, target_pointer->domain, target_pointer->length);
        name_str[target_pointer->length] = '\0';
        new_domain_name->domain = name_str;
        new_domain_name->length = target_pointer->length;
        if (first && target_pointer == last_domain_point) break;
        first = FALSE;
    }
    new_domain_name->next = NULL;
    return head;
}

int push_query(struct Message *msg) {
    int count = 0;
    struct Question *q;
    struct Question *pq;
    q = msg->questions;
    while (q) {
        count++;
        pq = malloc(sizeof(struct Question));
        memset(pq, 0, sizeof(struct Question));
        pq->qName = get_reply_domain(q->qName, NULL);
        pq->qType = q->qType;
        pq->qClass = q->qClass;
        pq->next = Queries;
        Queries = pq;

        q = q->next;
    }
    return count;
}

void delete_query()
{
    struct Question *next;
    next = Queries->next;
    free_domain_name(Queries->qName);
    free(Queries);
    Queries = next;
}
