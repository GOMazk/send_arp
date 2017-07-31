#Makefile
all: send_arp

send_arp: main.o packetheader.o
	g++ -o send_arp main.o packetheader.o -lpcap -w -Wall

main.o: main.c

packetheader.o: packetheader.c

clean:
	rm -f send_arp
	rm -f *.o
