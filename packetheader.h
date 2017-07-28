#pragma once


int analyze_packet( void* packet );
short int print_eth(struct Ethnet_header* eth);
int print_Ip4(struct Ip4_header* iph);
int print_Tcp(struct Tcp_header* tcph);
