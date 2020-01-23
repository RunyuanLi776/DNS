#ifndef _COMMON_H_
#define _COMMON_H_

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TRUE 1
#define FALSE 0
#define PORT_NUM 53
#define BUF_SIZE 6000

/* Response Type */
#define Ok_ResponseType 0
#define FormatError_ResponseType 1
#define ServerFailure_ResponseType 2
#define NameError_ResponseType 3
#define NotImplemented_ResponseType 4
#define Refused_ResponseType 5

/* Resource Record Types */
#define A_Resource_RecordType 1
#define NS_Resource_RecordType 2
#define CNAME_Resource_RecordType 5
#define SOA_Resource_RecordType 6
#define PTR_Resource_RecordType 12
#define MX_Resource_RecordType 15
#define TXT_Resource_RecordType 16
#define AAAA_Resource_RecordType 28
#define SRV_Resource_RecordType 33

/* Operation Code */
#define QUERY_OperationCode 0  /* standard query */
#define IQUERY_OperationCode 1 /* inverse query */
#define STATUS_OperationCode 2 /* server status request */
#define NOTIFY_OperationCode 4 /* request zone transfer */
#define UPDATE_OperationCode 5 /* change resource records */

/* Response Code */
#define NoError_ResponseCode 0
#define FormatError_ResponseCode 1
#define ServerFailure_ResponseCode 2
#define NameError_ResponseCode 3

/* Classes */
#define IN_Class 1

typedef int boolean;

struct DomainName {
    unsigned char *domain;
    uint8_t length;
    struct DomainName *next;
};

struct DomainNamePointer {
    unsigned char *name;
    uint8_t pos;
    uint8_t *header;
};

/* Question Section */
struct Question {
    struct DomainName *qName;
    uint16_t qType;
    uint16_t qClass;
    struct Question *next;
};

/* Data part of a Resource Record */
union ResourceData {
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        unsigned char *name;
    } cname_record;
    struct {
        uint16_t preference;
        unsigned char *exchange;
    } mx_record;
};

/* Resource Record Section */
struct ResourceRecord {
    struct DomainName *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rd_length;
    union ResourceData rd_data;
    struct ResourceRecord *next;
};

struct Message {
    uint16_t id; /* Identifier */

    /* Flags */
    uint16_t qr;     /* Query/Response Flag */
    uint16_t opcode; /* Operation Code */
    uint16_t aa;     /* Authoritative Answer Flag */
    uint16_t tc;     /* Truncation Flag */
    uint16_t rd;     /* Recursion Desired */
    uint16_t ra;     /* Recursion Available */
    uint16_t rcode;  /* Response Code */

    uint16_t qdCount; /* Question Count */
    uint16_t anCount; /* Answer Record Count */
    uint16_t nsCount; /* Authority Record Count */
    uint16_t arCount; /* Additional Record Count */

    /* At least one question; questions are copied to the response 1:1 */
    struct Question *questions;
    /*
    * Resource records to be send back.
    * Every resource record can be in any of the following places.
    * But every place has a different semantic.
    */
    struct ResourceRecord *answers;
    struct ResourceRecord *authorities;
    struct ResourceRecord *additionals;
};

/*
* Masks and constants.
*/
static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t RCODE_MASK = 0x000F;

size_t get8bits(uint8_t **);

size_t get16bits(uint8_t **);

size_t get32bits(uint8_t **);

void put8bits(uint8_t **, uint8_t);

void put16bits(uint8_t **, uint16_t);

void put32bits(uint8_t **, uint32_t);

void free_domain_name(struct DomainName *);

void free_resource_records(struct ResourceRecord *);

void free_questions(struct Question *);

unsigned char *structure_to_bytes(struct DomainName *);

void print_resource_record(struct ResourceRecord *);

void print_packet(struct Message *);

struct DomainName *decode_domain_name(uint8_t **, uint8_t *);

struct DomainName *decode_domain_name_from_byte(uint8_t *);

unsigned char *decode_domain_name_byte(unsigned char *);

unsigned char *encode_domain_name_string(unsigned char *);

void decode_header(struct Message *, uint8_t **);

void encode_header(struct Message *, uint8_t **);

void encode_domain_name(uint8_t **, struct DomainName *,
                        struct DomainNamePointer *);

int encode_resource_records(struct ResourceRecord *, uint8_t **,
                            struct DomainNamePointer *);

int encode_msg(struct Message *, uint8_t **);

void decode_resource_records(struct Message *, uint8_t **, int, uint16_t,
                             uint8_t *);

void decode_question(struct Message *, uint8_t **, uint8_t *);

int decode_msg(struct Message *, uint8_t *, int);

int encode_domain_name_mx_cname(uint8_t **buffer, unsigned char *buf_new,
                                struct DomainNamePointer *dnp);

#endif /* _COMMON_H_ */