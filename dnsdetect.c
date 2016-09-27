#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <resolv.h>
#include <stdint.h>
#include <unistd.h>


#include "constants.h"

#define LOG
// #define DEBUG

// global variables
int totalDNSResponseReceived = 0;
struct DNSResponseInfo dnsResponses[DNS_RESPONSES_MAX];
char *interface = NULL; // interface to be captured

//function headers
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
u_char* readName(unsigned char* reader,unsigned char* buffer,int* count);
const char *timestamp_string(struct timeval ts);
int isThereAnyCommon(char answers1[][IP_MAX_LENGTH], int answers1_count,
                     struct RES_RECORD answers[], int answers2_count);

int main(int argc, char **argv) {
	int iFlag = 0;
	int rFlag = 0;
	char *traceFile = NULL;
	char *BPFExpression = NULL;

	char dashI[] = "-i";
	char dashR[] = "-r";

	// Handling the program aguments
	int counter = 1;
	if (counter < argc && strcmp(dashI, argv[counter]) == 0) {
		iFlag = 1;
		counter++;
		interface = argv[counter];
		counter++;
	}
	if (counter < argc && strcmp(dashR, argv[counter]) == 0) {
		rFlag = 1;
		counter++;
		traceFile = argv[counter];
		counter++;
	}

    if (counter < argc) {
        int temp = counter;
        int bpfExpressionCounter = 0;
        while (temp < argc) {
            bpfExpressionCounter += (strlen(argv[temp])) + 1;
            temp++;
        }
        bpfExpressionCounter--;

        BPFExpression = (char *) malloc(bpfExpressionCounter * sizeof(char));
        int c = 0;
        while (counter < argc) {
            int c2;
            for (c2 = 0; c2 < strlen(argv[counter]); c2++) {
                BPFExpression[c++] = (argv[counter])[c2];
            }
            BPFExpression[c++] = ' ';
            counter++;
        }
        BPFExpression[--c] = '\0';
    }


#ifdef DEBUG
	printf("Debug::iFlag = %d, interface = %s, rFlag = %d, traceFile = %s, BPFExpression = %s\n",
		iFlag, interface, rFlag, traceFile, BPFExpression);
#endif

	// END handling the program aguments

	char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle;             /* packet capture handle */

    bpf_u_int32 mask;           /* subnet mask */
    bpf_u_int32 net;            /* ip */

    if (iFlag == 1 && rFlag == 1) {
        fprintf(stderr, "Error::The program either listens to the interface \"%s\" or reads packets from file \"%s\"\n",
            interface, traceFile);
        exit(EXIT_FAILURE);
    }
    else if (rFlag == 1) { // reading packets from the file
        handle = pcap_open_offline(traceFile, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error: Couldn't read the file: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else { // reading packets live from the interface passed to the program or default interface
        if (!(iFlag == 1)) { // reading packets live from the default interface
            /*
            pcap_lookupdev() returns a pointer to a string giving the name of a network device suitable for use with 
            pcap_create() and pcap_activate(), or with pcap_open_live(), and with pcap_lookupnet().
            */
            interface = pcap_lookupdev(errbuf);
            if (interface == NULL) {
                fprintf(stderr, "Error::Couldn't find default device: %s\n", errbuf);
                exit(EXIT_FAILURE);
            }
        }

        /*
        pcap_lookupnet() is used to determine the IPv4 network number and mask associated with the network device device.
        */
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Error::Couldn't get netmask for device %s: %s\n", interface, errbuf);
            net = 0;
            mask = 0;
        }

#ifdef DEBUG
        printf("Debug::Interface: %s\n", interface);
#endif        

        /*
        pcap_open_live() is used to obtain a packet capture handle to look at packets on the network.
        */
        handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error::Couldn't open device %s: %s\n", interface, errbuf);
            exit(EXIT_FAILURE);
        }

        /* make sure we're capturing on an Ethernet interface */
        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Error::%s is not an Ethernet\n", interface);
            exit(EXIT_FAILURE);
        }

    }

    struct bpf_program fp;          /* compiled filter program (expression) */
    if (BPFExpression != NULL) {
        /* compile the filter expression */
        if (pcap_compile(handle, &fp, BPFExpression, 0, net) == -1) {
            fprintf(stderr, "Error::Couldn't parse filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        /* apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error::Couldn't install filter %s: %s\n", BPFExpression, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    pcap_loop(handle, 0, process_packet, NULL);

    /* cleanup */
    if (BPFExpression != NULL)
        pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}


// This function gets called for each and every packet received.
// We will filter the packets which are not (udp && port == 53)
// For those packets which are dns-query, we will see whether:
//	- it is a query type A
//	- It's host name is inside the file
//	If the two conditions are valid, a spoofed reply will be forged to the network
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct ip *ip; // for IP header
	ip = (struct ip *) (packet + SIZE_ETHERNET);
	if (ip->ip_p != IPPROTO_UDP) {
#ifdef DEBUG
		// printf("process_packet::Debug::The packet is not of type UDP. So, it is ignored.\n");
#endif
		return;
	}

	struct udphdr *udp; // for UDP header
	udp = (struct udphdr *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H);
	if (ntohs(udp->source) != 53) {
#ifdef DEBUG
		// printf("process_packet::Debug::The packet is of type UDP. However, it's port is not 53 (it is %d). So, it is ignored.\n", udp->dest);
#endif
		return;
	}

	struct dnshdr *dns; // for DNS header
	dns = (struct dnshdr *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);

	char *dnsPayload; // pointer to DNS payload part of the packet
	dnsPayload = (char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);
	int dnsPayloadSize = strlen(dnsPayload);
	char hostName[MAX_HOSTNAME_LENGTH];
	/*
		source: http://linux.die.net/man/3/dn_expand
		The dn_expand(unsigned char *msg, unsigned char *eomorig,unsigned char *comp_dn, char *exp_dn,int length) 
		function expands the compressed domain name comp_dn to a full domain name, which is placed in the buffer
		exp_dn of size length. The compressed name is contained in a query or reply message, and msg points to 
		the beginning of the message.
	*/
	char *dnsPayload_bckup = dnsPayload;
	memset(hostName, '\0', sizeof(hostName));

	if (dn_expand((u_char *)dns, packet + (int)(header->caplen), dnsPayload,
		hostName, sizeof(hostName)) < 0) {
		printf("process_packet::Error:Couldn't expand the compressed domain name.\n");
		return;
	}

	dnsPayload = dnsPayload_bckup;
	hostName[dnsPayloadSize-1]='\0';


    char tempHostName[MAX_HOSTNAME_LENGTH];
    if (strncmp(hostName, "www", 3) != 0) { // it doesn't have www at the beginning 
        memset(tempHostName, '\0', sizeof(tempHostName));
        strncpy(tempHostName, "www.", 4);
        strncpy(tempHostName + 4, hostName, sizeof(hostName));
        strncpy(hostName, tempHostName, sizeof(tempHostName));
        
    }

#ifdef DEBUG
	printf("process_packet::Debug::DNS response detected (from %s:%d -> %s:%d), asking for %s.\n", inet_ntoa(ip->ip_src), ntohs(udp->source),
			inet_ntoa(ip->ip_dst), ntohs(udp->dest), hostName);
#endif

	unsigned char *buf = (unsigned char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);
	unsigned char *reader = &buf[sizeof(struct dnshdr) + (strlen((const char*)dnsPayload)+1) + sizeof(struct QUESTION)];
	struct RES_RECORD answers[MAX_ANSWER_RECORDED];
	

	int stop = 0;
	int i;
	int j;
	struct sockaddr_in a;

    int counter = 0;
    int hasAtLeastOneType_A = 0;
	for (i = 0; i < (ntohs(dns->ancount) <= MAX_ANSWER_RECORDED ? ntohs(dns->ancount) : MAX_ANSWER_RECORDED); i++) {
		answers[counter].name=readName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[counter].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[counter].resource->type) == T_A) { //if its an ipv4 address
            hasAtLeastOneType_A = 1;
            answers[counter].rdata = (unsigned char*) malloc(ntohs(answers[counter].resource->data_len));
            for(j=0 ; j<ntohs(answers[counter].resource->data_len) ; j++) {
                answers[counter].rdata[j]=reader[j];
            }
            answers[counter].rdata[ntohs(answers[counter].resource->data_len)] = '\0';
            reader = reader + ntohs(answers[counter].resource->data_len);
            counter++;
        } else {
            answers[counter].rdata = readName(reader,buf,&stop);
            reader = reader + stop;
            counter++;
        }
	}

#ifdef DEBUG

    printf("\nAnswer Records : %d \n" , ntohs(dns->ancount) );
    for(i=0 ; i < ntohs(dns->ancount) ; i++)
    {
        printf("Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) { //IPv4 address
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) {
            //Canonical name for an alias
            printf("has alias name : %s",answers[i].rdata);
        }
 
        printf("\n");
    }

#endif

    if (hasAtLeastOneType_A == 0) {
#ifdef DEBUG
        printf("process_packet::Debug::The response doesn't have any TYPE_A response. ignoring\n");
#endif
        return;
    }

    int attackDetected = 0;
    for (i = 0; i < totalDNSResponseReceived; i++) {
        if ((dnsResponses[i].id == (int) dns->id) && (strcmp(dnsResponses[i].hostName, hostName) == 0)) { // dnsResponses[i].id == (int) dns->id
            if (isThereAnyCommon(dnsResponses[i].answers, dnsResponses[i].answerCount, answers, ntohs(dns->ancount)) == 0) {
                attackDetected = 1;
                break;
            }
        }
    }

    if (attackDetected == 1) {

        printf("%s DNS poisoning attempt\n", timestamp_string(header->ts));
        printf("TXID %d Request %s\n", (int) dns->id, hostName);
        printf("Answer1 [");
        for (j = 0; j < dnsResponses[i].answerCount; j++)
            printf("%s   ", dnsResponses[i].answers[j]);
        printf("]\n");

        printf("Answer2 [");
        for (j = 0; j < ntohs(dns->ancount); j++) {
            if( ntohs(answers[j].resource->type) == T_A) { //IPv4 address 
                long *p;
                p=(long*)answers[j].rdata;
                a.sin_addr.s_addr=(*p); //working without ntohl
                printf("%s   ", inet_ntoa(a.sin_addr));
            }
        }
        printf("]\n");        
        printf("--------------------------\n\n");
    }
    else {
#ifdef DEBUG
        printf("process_packet::Debug::there is no DNS poisoning attempt. Value of totalDNSResponseReceived is %d\n", totalDNSResponseReceived);
        printf("process_packet::Debug::(int) dns->id=%d, hostName=%s\n", (int) dns->id, hostName);
#endif        
        if (hasAtLeastOneType_A == 1) {
            dnsResponses[totalDNSResponseReceived].id = (int) dns->id;
            strcpy(dnsResponses[totalDNSResponseReceived].hostName, hostName);
            dnsResponses[totalDNSResponseReceived].answerCount = 0;
            for(j = 0 ; j < (ntohs(dns->ancount) <= MAX_ANSWER_RECORDED ? ntohs(dns->ancount) : MAX_ANSWER_RECORDED); j++) {
                if( ntohs(answers[j].resource->type) == T_A) { //IPv4 address 
                    long *p;
                    p=(long*)answers[j].rdata;
                    a.sin_addr.s_addr=(*p); //working without ntohl

                    strncpy(dnsResponses[totalDNSResponseReceived].answers[dnsResponses[totalDNSResponseReceived].answerCount],
                        inet_ntoa(a.sin_addr), IP_MAX_LENGTH);
                    dnsResponses[totalDNSResponseReceived].answerCount++;
                }           
            }
            totalDNSResponseReceived++;
        }
    }
}

/*
// This function takes out the hostName inside the answer resource record of the DNS response !!
// copyright-NOTE: this function (and some of the structs used in the program) has been obtained from the 
// following link (which illustrates how to do DNS query in C using linux sockets):
//      http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
*/
u_char* readName(unsigned char* reader,unsigned char* buffer,int* count) {
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*) malloc(256);
 
    name[0]='\0';
 
    while(*reader!=0) {
        if(*reader>=192) {
            offset = (*reader) * 256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0) {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1) {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)name);i++) {
        p=name[i];
        for(j=0;j<(int)p;j++) {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}


// copyright-NOTE: copied from HW#2
const char *timestamp_string(struct timeval tv){
    char mbuff[64];
    static char buff[64];

    time_t time = (time_t)tv.tv_sec;
    strftime(mbuff, 20, "%Y-%m-%d %H:%M:%S", localtime(&time));
    snprintf(buff, sizeof buff, "%s.%06d", mbuff, (int)tv.tv_usec);
    return buff;
}

// This function checks whether there exist a common IP address in two packets
int isThereAnyCommon(char answers1[][IP_MAX_LENGTH], int answers1_count,
                     struct RES_RECORD answers[], int answers2_count) {

    int i;
    for (i = 0; i < answers1_count; i++) {
        int j;
        for (j = 0; j < answers2_count; j++) {
            if (ntohs(answers[j].resource->type) == T_A) {
                struct sockaddr_in a;
                long *p;
                p=(long*)answers[j].rdata;
                a.sin_addr.s_addr=(*p);
                if (strcmp(answers1[i], inet_ntoa(a.sin_addr)) == 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}
