#include "common.h"

/*
* Basic memory operations.
*/

size_t get8bits(uint8_t **buffer) {
    uint8_t value;
    memcpy(&value, *buffer, 1);
    *buffer += 1;
    return value;
}

size_t get16bits(uint8_t **buffer) {
    uint16_t value;
    memcpy(&value, *buffer, 2);
    *buffer += 2;
    return ntohs(value);
}

size_t get32bits(uint8_t **buffer) {
    uint32_t value;
    memcpy(&value, *buffer, 4);
    *buffer += 4;
    return ntohl(value);
}

void put8bits(uint8_t **buffer, uint8_t value) {
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value) {
    value = htons(value);
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value) {
    value = htonl(value);
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

void free_domain_name(struct DomainName *dm) {
    if (dm == NULL) return;
    struct DomainName *next;
    while (dm) {
        next = dm->next;
        free(dm);
        dm = next;
    }
}

void free_resource_records(struct ResourceRecord *rr) {
    if (rr == NULL) return;
    struct ResourceRecord *next;

    while (rr) {
        free_domain_name(rr->name);
        next = rr->next;
        free(rr);
        rr = next;
    }
}

void free_questions(struct Question *qq) {
    if (qq == NULL) return;
    struct Question *next;

    while (qq) {
        free_domain_name(qq->qName);
        next = qq->next;
        free(qq);
        qq = next;
    }
}

unsigned char *structure_to_bytes(struct DomainName *domainName) {
    struct DomainName *domain = domainName;
    unsigned char *nameStr;
    nameStr = malloc(sizeof(unsigned char) * 255);
    memset(nameStr, 0, sizeof(unsigned char) * 255);
    unsigned char *orig_nameStr = nameStr;
    encode_domain_name(&nameStr, domain, NULL);
    return orig_nameStr;
}

void print_resource_record(struct ResourceRecord *rr) {
    int i;
    while (rr) {
        printf("Name:%s\n* Type:%u\n* TTL:%d\n* rd_length:%u\n",
               decode_domain_name_byte(structure_to_bytes(rr->name)), rr->type,
               rr->ttl, rr->rd_length);
        printf("Answer: \n");
        union ResourceData *rd = &rr->rd_data;
        switch (rr->type) {
            case A_Resource_RecordType:
                printf("address:");
                for (i = 0; i < 4; ++i)
                    printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
                printf("\n");
                break;
            case CNAME_Resource_RecordType:
                printf("CNAME:%s\n",
                       decode_domain_name_byte(rd->cname_record.name));
                break;
            case MX_Resource_RecordType:
                printf("MX Record preference:%u exchange:%s\n",
                       rd->mx_record.preference,
                       decode_domain_name_byte(rd->mx_record.exchange));
                break;
            default:
                printf("Unknown Resource Record\n");
        }
        rr = rr->next;
    }
}

void print_packet(struct Message *msg) {
    struct Question *q = msg->questions;
    printf("Question:\n");
    while (q) {
        printf("DNS NAME:%s\n",
               decode_domain_name_byte(structure_to_bytes(q->qName)));
        printf("DNS TYPE:%u\n", q->qType);
        printf("DNS CLASS:%u\n", q->qClass);
        q = q->next;
    }

    if (msg->anCount > 0) {
        printf("\n");
        printf("DNS ANSWER SECTION:\n");
        print_resource_record(msg->answers);
    }
    if (msg->nsCount > 0) {
        printf("\n");
        printf("DNS AUTHORITY SECTION:\n");
        print_resource_record(msg->authorities);
    }

    if (msg->arCount > 0) {
        printf("\n");
        printf("DNS ADDITIONAL SECTION:\n");
        print_resource_record(msg->additionals);
    }
}

void decode_header(struct Message *msg, uint8_t **buffer) {
    msg->id = get16bits(buffer);

    uint32_t fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK) >> 0;

    msg->qdCount = get16bits(buffer);
    msg->anCount = get16bits(buffer);
    msg->nsCount = get16bits(buffer);
    msg->arCount = get16bits(buffer);
}

void encode_header(struct Message *msg, uint8_t **buffer) {
    put16bits(buffer, msg->id);

    int fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->rd << 8) & RD_MASK;
    fields |= (msg->ra << 7) & RA_MASK;
    fields |= (msg->rcode << 0) & RCODE_MASK;
    put16bits(buffer, fields);

    put16bits(buffer, msg->qdCount);
    put16bits(buffer, msg->anCount);
    put16bits(buffer, msg->nsCount);
    put16bits(buffer, msg->arCount);
}

void decode_question(struct Message *msg, uint8_t **buffer, uint8_t *header) {
    int i;
    for (i = 0; i < msg->qdCount; ++i) {
        struct Question *q;
        q = malloc(sizeof(struct Question));
        memset(q, 0, sizeof(struct Question));
        q->qName = decode_domain_name(buffer, header);
        q->qType = get16bits(buffer);
        q->qClass = get16bits(buffer);
        q->next = msg->questions;
        msg->questions = q;
    }
}

int decode_msg(struct Message *msg, uint8_t *buffer, int size) {
    uint8_t *header = buffer;
    decode_header(msg, &buffer);
    decode_question(msg, &buffer, header);
    decode_resource_records(msg, &buffer, 1, msg->anCount, header);
    decode_resource_records(msg, &buffer, 2, msg->nsCount, header);
    decode_resource_records(msg, &buffer, 3, msg->arCount, header);

    return 0;
}

int encode_msg(struct Message *msg, uint8_t **buffer) {
    struct Question *q;
    int rc;
    struct DomainNamePointer *dnp;
    dnp = malloc(sizeof(struct DomainNamePointer));
    memset(dnp, 0, sizeof(struct DomainNamePointer));
    dnp->header = *buffer;
    encode_header(msg, buffer);

    q = msg->questions;
    while (q) {
        encode_domain_name(buffer, q->qName, dnp);
        put16bits(buffer, q->qType);
        put16bits(buffer, q->qClass);

        q = q->next;
    }

    rc = 0;
    rc |= encode_resource_records(msg->answers, buffer, dnp);
    rc |= encode_resource_records(msg->authorities, buffer, dnp);
    rc |= encode_resource_records(msg->additionals, buffer, dnp);

    return rc;
}

void decode_resource_records(struct Message *msg, uint8_t **buffer, int section,
                             uint16_t count, uint8_t *header) {
    if (count <= 0) return;
    int i, j;
    for (i = 0; i < count; ++i) {
        struct ResourceRecord *rr;
        rr = malloc(sizeof(struct ResourceRecord));
        memset(rr, 0, sizeof(struct ResourceRecord));
        rr->name = decode_domain_name(buffer, header);
        rr->type = get16bits(buffer);
        rr->class = get16bits(buffer);
        rr->ttl = get32bits(buffer);
        rr->rd_length = get16bits(buffer);
        switch (rr->type) {
            case A_Resource_RecordType:
                for (j = 0; j < 4; ++j) {
                    rr->rd_data.a_record.addr[j] = get8bits(buffer);
                }
                break;
            case MX_Resource_RecordType:
                rr->rd_data.mx_record.preference = get16bits(buffer);
                rr->rd_data.mx_record.exchange =
                    structure_to_bytes(decode_domain_name(buffer, header));
                break;
            case CNAME_Resource_RecordType:
                rr->rd_data.cname_record.name =
                    structure_to_bytes(decode_domain_name(buffer, header));
                break;

            default:
                fprintf(stderr, "Unknown type %u. => Ignore resource record.\n",
                        rr->type);
                break;
        }
        if (section == 1) {
            rr->next = msg->answers;
            msg->answers = rr;
        } else if (section == 2) {
            rr->next = msg->authorities;
            msg->authorities = rr;
        } else if (section == 3) {
            rr->next = msg->additionals;
            msg->additionals = rr;
        }
    }
}

// 3foo3bar3com0 => foo.bar.com
unsigned char *decode_domain_name_byte(unsigned char *domain) {
    unsigned char *name;
    name = malloc(sizeof(unsigned char) * 256);
    memset(name, 0, sizeof(unsigned char) * 256);
    uint8_t *buf = domain;
    int j = 0;
    int i = 0;

    while (buf[i] != 0) {
        if (i != 0) {
            strncat(name, ".", 1);
            j += 1;
        }

        int len = buf[i];
        i += 1;

        memcpy(name + j, buf + i, len);
        i += len;
        j += len;
    }

    name[j] = '\0';

    return strdup(name);
}

// foo.bar.com => 3foo3bar3com0
unsigned char *encode_domain_name_string(unsigned char *domain) {
    unsigned char *buf;
    buf = malloc(sizeof(unsigned char) * 256);
    memset(buf, 0, sizeof(unsigned char) * 256);
    unsigned char *pointer = domain;
    unsigned char *pos;
    int len = 0;
    int i = 0;
    while ((pos = strchr(pointer, '.'))) {
        len = pos - pointer;
        buf[i] = len;
        i += 1;
        memcpy(buf + i, pointer, len);
        i += len;

        pointer = pos + 1;
    }
    len = strlen(domain) - (pointer - domain);
    buf[i] = len;
    i += 1;
    memcpy(buf + i, pointer, len);
    i += len;
    buf[i] = 0;
    i += 1;
    return strdup(buf);
}

// 3foo3bar3com0 => foo.bar.com
struct DomainName *decode_domain_name(uint8_t **buffer, uint8_t *header) {
    struct DomainName *name = NULL;

    uint8_t *buf = *buffer;
    uint8_t *buf_reverse;
    int i = 0, j = 0, k = 0, l = 0;
    boolean first = TRUE;
    name = malloc(sizeof(struct DomainName));
    memset(name, 0, sizeof(struct DomainName));
    struct DomainName *head = name;

    uint8_t *buf_express;
    int compress_pointer = 0;
    uint8_t *copy_addr;
    buf_express = malloc(sizeof(uint8_t) * 255);
    memset(buf_express, 0, sizeof(uint8_t) * 255);
    int buffer_moved = 0;
    int buf_express_len = 0;
    copy_addr = buf;

    while (copy_addr[l] != 0) {
        if (copy_addr[l] >= 0xc0) {
            compress_pointer =
                copy_addr[l] * (16 * 16) + copy_addr[l + 1] - 0xc0 * (16 * 16);
            copy_addr = header + compress_pointer;
            buffer_moved += l + 2;
            l = 0;
        }
        uint8_t len = copy_addr[l];
        memcpy(buf_express + buf_express_len, copy_addr + l, 1);
        l += 1;
        buf_express_len += 1;
        memcpy(buf_express + buf_express_len, copy_addr + l, len);
        l += len;
        buf_express_len += len;
    }
    buf_express[buf_express_len] = 0;

    buf_reverse = malloc(sizeof(uint8_t) * (strlen(buf_express) + 1));
    memset(buf_reverse, 0, sizeof(uint8_t) * (strlen(buf_express) + 1));
    uint8_t **reverse;
    reverse = (uint8_t **)malloc(sizeof(uint8_t *) * 256);

    while (buf_express[j] != 0) {
        uint8_t len_reverse = buf_express[j];
        uint8_t *temp_reverse;
        temp_reverse = malloc(sizeof(uint8_t) * (len_reverse + 1 + 1));
        memset(temp_reverse, 0, sizeof(uint8_t) * (len_reverse + 1 + 1));
        temp_reverse[0] = buf_express[j];
        j += 1;
        memcpy(temp_reverse + 1, buf_express + j, len_reverse);
        reverse[k] = temp_reverse;
        j += len_reverse;
        k += 1;
    }
    int length_now = 0;
    for (j = k - 1; j >= 0; j--) {
        memcpy(buf_reverse + length_now, reverse[j], strlen(reverse[j]));
        length_now += strlen(reverse[j]);
    }

    while (buf_reverse[i] != 0) {
        if (!first) {
            name->next = malloc(sizeof(struct DomainName));
            memset(name->next, 0, sizeof(struct DomainName));
            name = name->next;
        }
        first = FALSE;
        uint8_t len = buf_reverse[i];
        i += 1;
        unsigned char *name_str;
        name_str = malloc(sizeof(unsigned char) * (len + 1));
        memset(name_str, 0, sizeof(unsigned char) * (len + 1));
        memcpy(name_str, buf_reverse + i, len);
        name_str[len] = '\0';
        name->domain = name_str;
        name->length = len;
        i += len;
    }
    if (buffer_moved != 0)
        *buffer += buffer_moved;
    else
        *buffer += i + 1;

    return head;
}

// 3foo3bar3com0 => foo.bar.com structure
struct DomainName *decode_domain_name_from_byte(uint8_t *buffer) {
    struct DomainName *name = NULL;

    uint8_t *buf = buffer;
    int i = 0, j = 0, k = 0;
    boolean first = TRUE;
    name = malloc(sizeof(struct DomainName));
    memset(name, 0, sizeof(struct DomainName));
    uint8_t *buf_new;
    buf_new = malloc(sizeof(uint8_t) * strlen(buf) + 1);
    memset(buf_new, 0, sizeof(uint8_t) * strlen(buf) + 1);
    uint8_t **reverse;
    reverse = (uint8_t **)malloc(sizeof(uint8_t *) * 256);
    struct DomainName *head = name;
    while (buf[j] != 0) {
        uint8_t len_reverse = buf[j];
        uint8_t *temp_reverse;
        temp_reverse = malloc(sizeof(uint8_t) * (len_reverse + 1 + 1));
        memset(temp_reverse, 0, sizeof(uint8_t) * (len_reverse + 1 + 1));
        temp_reverse[0] = buf[j];
        j += 1;
        memcpy(temp_reverse + 1, buf + j, len_reverse);
        reverse[k] = temp_reverse;
        j += len_reverse;
        k += 1;
    }
    int length_now = 0;
    for (j = k - 1; j >= 0; j--) {
        memcpy(buf_new + length_now, reverse[j], strlen(reverse[j]));
        length_now += strlen(reverse[j]);
    }

    while (buf_new[i] != 0) {
        if (!first) {
            name->next = malloc(sizeof(struct DomainName));
            memset(name->next, 0, sizeof(struct DomainName));
            name = name->next;
        }
        first = FALSE;
        uint8_t len = buf_new[i];
        i += 1;
        unsigned char *name_str;
        name_str = malloc(sizeof(unsigned char) * (len + 1));
        memset(name_str, 0, sizeof(unsigned char) * (len + 1));
        memcpy(name_str, buf_new + i, len);
        name_str[len] = '\0';
        name->domain = name_str;
        name->length = len;
        i += len;
    }

    name->next = NULL;
    return head;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t **buffer, struct DomainName *domainName,
                        struct DomainNamePointer *dnp) {
    uint8_t *buf = *buffer;
    struct DomainName *domain = domainName;

    uint8_t *buf_orig;
    int len = 0;

    while (domain->next != NULL) {
        len++;
        len += domain->length;
        domain = domain->next;
    }
    len++;
    len += domain->length;
    len++;
    buf_orig = malloc(sizeof(uint8_t) * len);
    memset(buf_orig, 0, sizeof(uint8_t) * len);
    domain = domainName;

    int l = 0;

    while (domain->next != NULL) {
        buf_orig[l] = domain->length;
        l++;
        memcpy(buf_orig + l, domain->domain, domain->length);
        l += domain->length;
        domain = domain->next;
    }
    buf_orig[l] = domain->length;
    l++;
    memcpy(buf_orig + l, domain->domain, domain->length);

    domain = domainName;

    uint8_t *buf_new;
    int j = 0, k = 0;
    buf_new = malloc(sizeof(uint8_t) * (len + 1));
    memset(buf_new, 0, sizeof(uint8_t) * (len + 1));
    uint8_t **reverse = (uint8_t **)malloc(sizeof(uint8_t *) * 256);

    while (buf_orig[j] != 0) {
        uint8_t len_reverse = buf_orig[j];
        uint8_t *temp_reverse;
        temp_reverse = malloc(sizeof(uint8_t) * (len_reverse + 1 + 1));
        memset(temp_reverse, 0, sizeof(uint8_t) * (len_reverse + 1 + 1));
        temp_reverse[0] = buf_orig[j];
        j += 1;
        memcpy(temp_reverse + 1, buf_orig + j, len_reverse);
        reverse[k] = temp_reverse;
        j += len_reverse;
        k += 1;
    }

    int length_now = 0;
    for (j = k - 1; j >= 0; j--) {
        memcpy(buf_new + length_now, reverse[j], strlen(reverse[j]));
        length_now += strlen(reverse[j]);
    }

    int position = -1;
    int position2 = -1;

    boolean has_dnp = FALSE;
    if (dnp != NULL) {
        if (dnp->pos != 0) {
            has_dnp = TRUE;
        }
    }

    if (has_dnp) {
        unsigned char *substring;
        substring = dnp->name;
        while (substring[0] != '\0') {
            unsigned char *substring2;
            substring2 = strstr(buf_new, substring);
            if (substring2 != NULL) {
                position = strlen(dnp->name) - strlen(substring2);
                position2 = strlen(buf_new) - strlen(substring2);
                break;
            } else {
                substring += (uint8_t)substring[0] + 1;
            }
        }
    } else if (dnp != NULL) {
        if (dnp->header != NULL) {
            dnp->name = strdup(buf_new);
            dnp->pos = *buffer - dnp->header;
        }
    }

    if (position >= 0 && position2 >= 0) {
        memcpy(buf, buf_new, position2);
        *buffer += position2;
        int fields = 0;
        fields |= (1 << 15) & 0x8000;
        fields |= (1 << 14) & 0x4000;
        fields += dnp->pos + position;
        put16bits(buffer, fields);

    } else {
        memcpy(buf, buf_new, len);
        buf[len] = 0;
        *buffer += len;
    }
}

// foo.bar.com => 3foo3bar3com0
int encode_domain_name_mx_cname(uint8_t **buffer, unsigned char *buf_new,
                                struct DomainNamePointer *dnp) {
    uint8_t *buf = *buffer;

    int len = strlen(buf_new) + 1;

    int position = -1;
    int position2 = -1;

    int has_dnp = 0;
    if (dnp != NULL) {
        if (dnp->pos != 0) {
            has_dnp = 1;
        }
    }
    if (has_dnp) {
        unsigned char *substring;
        substring = dnp->name;
        while (substring[0] != '\0') {
            unsigned char *substring2;
            substring2 = strstr(buf_new, substring);
            if (substring2 != NULL) {
                position = strlen(dnp->name) - strlen(substring2);
                position2 = strlen(buf_new) - strlen(substring2);
                break;
            } else {
                substring += (uint8_t)substring[0] + 1;
            }
        }
    } else if (dnp != NULL) {
        if (dnp->header != NULL) {
            dnp->name = strdup(buf_new);
            dnp->pos = *buffer - dnp->header;
        }
    }

    if (position >= 0 && position2 >= 0) {
        memcpy(buf, buf_new, position2);
        *buffer += position2;
        int fields = 0;
        fields |= (1 << 15) & 0x8000;
        fields |= (1 << 14) & 0x4000;
        fields += dnp->pos + position;
        put16bits(buffer, fields);
        return position2 + 2;  // 2是fields的长度
    } else {
        memcpy(buf, buf_new, len);
        buf[len] = 0;
        // len+=1;
        *buffer += len;
        return len;
    }
}

/* @return 0 upon failure, 1 upon success */
int encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer,
                            struct DomainNamePointer *dnp) {
    int i, new_rd_length;
    uint8_t *rd_length_pos;
    while (rr) {
        encode_domain_name(buffer, rr->name, dnp);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->class);
        put32bits(buffer, rr->ttl);
        rd_length_pos = *buffer;
        put16bits(buffer, rr->rd_length);

        switch (rr->type) {
            case A_Resource_RecordType:
                for (i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
            case MX_Resource_RecordType:
                put16bits(buffer, rr->rd_data.mx_record.preference);
                new_rd_length = encode_domain_name_mx_cname(
                    buffer, rr->rd_data.mx_record.exchange, dnp);
                put16bits(
                    &rd_length_pos,
                    new_rd_length + 2);  //这个2是mx_record.preference的长度

                break;
            case CNAME_Resource_RecordType:
                new_rd_length = encode_domain_name_mx_cname(
                    buffer, rr->rd_data.cname_record.name, dnp);
                put16bits(&rd_length_pos, new_rd_length);
                break;
            default:
                fprintf(stderr, "Unknown type %u. => Ignore resource record.\n",
                        rr->type);
                break;
                return 1;
        }

        rr = rr->next;
    }

    return 0;
}
