#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Ethernet Header\n");
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
				// ethernet header 의 MAC 주소는 6 바이트로 구성되어 있음.
				// ethernet header 에서 목적지 MAC 주소, 출발지 MAC 주소를 출력함.

        printf("IP Header\n");
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
				// 출발지 IP, 도착지 IP 정보를 출력함.

        // Determine protocol
        switch (ip->iph_protocol) { // 상위 프로토콜의 타입을 파악함.
            case IPPROTO_TCP: {
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

                printf("Protocol: TCP\n");
                printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
                printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

                int data_len = ntohs(ip->iph_len) - (ip->iph_ihl << 2) - (TH_OFF(tcp) << 2);
				// 데이터 영역의 길이는 IP 패킷의 전체 길이(iph_len)에서 IP 헤더 길이(iph_ihl)와 TCP 헤더 길이(th_off)를 빼서 계산함.

                int max_message_len = 100; // TCP 데이터 영역을 추출 후 최대 100 바이트를 출력함.
                int print_len = data_len < max_message_len ? data_len : max_message_len;
                const u_char *message_data = packet + sizeof(struct ethheader) + (ip->iph_ihl << 2) + (TH_OFF(tcp) << 2);
								// IP 헤더와 TCP 헤더의 길이 정보를 이용하여 데이터 영역의 시작 위치를 계산함.
								// 해당 위치부터 data_len 만큼의 데이터를 메시지로 출력함.

                printf("Message (%d bytes):\n", print_len);
                for (int i = 0; i < print_len; i++) {
                    if (isprint(message_data[i])) {
                        printf("%c", message_data[i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n");
                break;
            }
            case IPPROTO_UDP:
                printf("Protocol: UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("Protocol: ICMP\n");
                break;
            default:
                printf("Protocol: others\n");
                break;
        }
        printf("\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s1
    handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open interface: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}