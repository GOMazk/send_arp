#pragma once


int arp_spoof(char* out_packet, char* in_packet);
int check_arp_type(struct Arp_header* arph, uint16_t htype, uint16_t ptype, uint8_t hlen, uint8_t plen );
int analyze_packet( void* packet );
short int print_eth(struct Ethnet_header* eth);
int print_Ip4(struct Ip4_header* iph);
int print_Tcp(struct Tcp_header* tcph);
