#ifndef _CONSTANTS
#define _CONSTANTS


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define MAX_FORGED_HOSTNAMES 100
#define IP_MAX_LENGTH 16
#define MAX_HOSTNAME_LENGTH 128

#define DNS_RESPONSES_MAX 1000
#define MAX_ANSWER_RECORDED 20

// USED ON BOTH dnsinject.c and dnsdetect.c programs
struct dnshdr   {
    unsigned    id:      16;
    unsigned    rd:       1;
    unsigned    tc:       1;
    unsigned    aa:       1;
    unsigned    opcode:   4;
    unsigned    qr:       1;
    unsigned    rcode:    4;
    unsigned    cd:       1;
    unsigned    ad:       1;
    unsigned    unused:   1;
    unsigned    ra:       1;
    unsigned    qdcount: 16;
    unsigned    ancount: 16;
    unsigned    nscount: 16;
    unsigned    arcount: 16;
};

// FOLLOWING STRUCTURS AND CONSTANS USED ONLY IN dnsdetect.c program

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

struct DNSResponseInfo{
    int id;
    char hostName[MAX_HOSTNAME_LENGTH];
    int answerCount;
    char answers[MAX_ANSWER_RECORDED][IP_MAX_LENGTH];
};

#endif