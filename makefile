all: SniferEx
	

SniferEx: main.o NetSniffer.o Md5HashedPayload.o
	g++ main.o NetSniffer.o Md5HashedPayload.o -lpcap -lcrypto -o SniferEx

main.o: main.cpp NetSniffer.hpp TcpIpInternetHeaders.hpp Md5HashedPayload.hpp
	g++ -c main.cpp -o main.o

NetSniffer.o: NetSniffer.cpp NetSniffer.hpp
	g++ -c NetSniffer.cpp -o NetSniffer.o

Md5CachedPayload.o: Md5HashedPayload.cpp Md5HashedPayload.hpp
	g++ -c Md5HashedPayload.cpp -o Md5HashedPayload.o

clean:
	rm -rf *.o
