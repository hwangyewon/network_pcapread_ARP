#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <cstdio>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>

using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res==0)continue;
        if(res==-1 || res==-2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet, header);
    }

    pcap_close(handle);
    
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header)
{
    struct ether_header *eth_hdr = (struct ether_header *)pkt_data;
    u_int16_t eth_type = ntohs(eth_hdr->ether_type);

    //if type is not ARP, return function
    if(eth_type!=ETHERTYPE_ARP) return;

    struct ether_arp *arp_hdr = (struct ether_arp *)(pkt_data+sizeof(ether_header));


    printf("\nPacket Info====================================\n");

    //print pkt length
    printf("%u bytes captured\n", header->caplen);

    //print mac addr
    u_int8_t *dst_mac = eth_hdr->ether_dhost;
    u_int8_t *src_mac = eth_hdr->ether_shost;

    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0],src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    

    //print sender MAC addr
    u_int8_t *send_mac = arp_hdr->arp_sha;
    printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
    send_mac[0],send_mac[1], send_mac[2], send_mac[3], send_mac[4], send_mac[5]);
    
    //print sender ip addr
    char send_ip[16];
    char* tmp = inet_ntoa(*(struct in_addr *)&arp_hdr->arp_spa);
    strcpy(send_ip, tmp);

    printf("Sender IP : %s\n", send_ip);


    //print target MAC addr
    u_int8_t *tar_mac = arp_hdr->arp_tha;
    printf("Target MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
    tar_mac[0],tar_mac[1], tar_mac[2], tar_mac[3], tar_mac[4], tar_mac[5]);


    //print target ip addr
    char tar_ip[16];
    tmp = inet_ntoa(*(struct in_addr *)&arp_hdr->arp_tpa);
    strcpy(tar_ip, tmp);

    printf("Target IP : %s\n", tar_ip);




    //print payload
    // u_int32_t payload_len = header->caplen - sizeof(ether_header) - ip_offset*4;
    // u_int32_t max = payload_len >= 16 ? 16 : payload_len;
    // const u_char* pkt_payload = pkt_data + sizeof(ether_header)+ip_offset*4;
    // printf("Payload : ");

    // if(!payload_len){
    //     printf("No payload\n");
    // }else{
    //     for(int i=0;i<max;i++) printf("%02x ", *(pkt_payload+i));
    //     printf("\n");
    // }
}