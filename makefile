all: SniferEx
	

SniferEx: main.o NetSniffer.o Md5CachedPayload.o
	g++ main.o NetSniffer.o Md5CachedPayload.o -lpcap -lcrypto -o SniferEx

main.o: main.cpp NetSniffer.hpp TcpIpInternetHeaders.hpp Md5CachedPayload.hpp
	g++ -c main.cpp -o main.o

NetSniffer.o: NetSniffer.cpp NetSniffer.hpp
	g++ -c NetSniffer.cpp -o NetSniffer.o

Md5CachedPayload.o: Md5CachedPayload.cpp Md5CachedPayload.hpp
	g++ -c Md5CachedPayload.cpp -o Md5CachedPayload.o

clean:
	rm -rf *.o
