#include <pcap.h>
#include <stdio.h>
#include "packetheader.h"


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	
	/* Define the device */
	if(argc >= 2){
		dev = argv[1];
	}
	else{	//case: no input
		dev = pcap_lookupdev(errbuf);
	}

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("getting from device - %s\n",dev);


	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	printf("start\n");
	while(1){
		/* Grab a packet */
		switch(pcap_next_ex(handle,&header,&packet)){
			case 1:
				analyze_packet(packet);
				break;
			case 0:
				printf("listening..\n");
				break;
			case -1:
				printf("error occurred\n");
				return(2);
				break;
			case -2:
				printf("end of file\n");
				return(2);
				break;
		}
	}
	/* And close the session */
	pcap_close(handle);
	return(0);
}
