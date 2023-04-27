#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "structPcap.h"

// usage()
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

// Param구조체
// *char형 dev_=NULL 선언
typedef struct {
	char* dev_;
} Param;
Param param = {
	.dev_ = NULL
};


// boolean type parse함수선언
// argc2가 아니면 usage()호출
// argv[1]에 param을 dev_로 역으로 참조
bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


int main(int argc, char* argv[]) {

	//충족하지 않으면 return -1로 종료
	if (!parse(&param, argc, argv))
		return -1;
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	// NULL이면 큰일남
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	} 

	//16진수 하나씩 출력하는 부분임
	while (1) {
		// 구조체 멤버변수, u_char형 선언
		struct pcap_pkthdr *hd;
        const u_char *pk;
        int res = pcap_next_ex(pcap,&hd, &pk);

        if(res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        
        // hd->caplen # packetLength
		// htonl()으로 바이트오더링 설정해야되는데 못함
        const struct eth_hdr* pk_eth = (const struct eth_hdr*)pk;
		printf("srcMAC: ");
        for (int i = 0; i < ETH_ALEN; ++i) {
            printf("%s%02X", (i ? ":" : ""), pk_eth->src[i]);
        }
        printf(" |dstMac: ");
        for (int i = 0; i < ETH_ALEN; ++i) {
            printf("%s%02X", (i ? ":" : ""), pk_eth->dst[i]);
        }puts("");

		//ipv4가 아닐때 체크
        int eth_type = ntohs(pk_eth->type);
        if(eth_type!=0x0800){
            puts("Ethertype : not ipv4\n");
            continue;
        }
	}
	pcap_close(pcap); // 사용후엔 종료
}
