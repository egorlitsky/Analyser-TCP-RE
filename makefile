all: SniferEx
	

SniferEx: main.o NetSniffer.o
	g++ main.o NetSniffer.o -lpcap -o SniferEx

main.o: main.cpp NetSniffer.hpp TcpIpInternetHeaders.hpp
	g++ -c main.cpp -o main.o

NetSniffer.o: NetSniffer.cpp NetSniffer.hpp
	g++ -c NetSniffer.cpp -o NetSniffer.o

clean:
	rm -rf *.o
