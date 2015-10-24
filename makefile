all: SniferEx
	

SniferEx: main.o NetSniffer.o Md5HashedPayload.o CacheStructure.o
	g++ -std=c++11 main.o NetSniffer.o Md5HashedPayload.o -lpcap -lcrypto -o SniferEx

main.o: main.cpp NetSniffer.hpp TcpIpInternetHeaders.hpp Md5HashedPayload.hpp
	g++ -std=c++11 -c main.cpp -o main.o

NetSniffer.o: NetSniffer.cpp NetSniffer.hpp
	g++ -std=c++11 -std=c++11 -c NetSniffer.cpp -o NetSniffer.o

Md5CachedPayload.o: Md5HashedPayload.cpp Md5HashedPayload.hpp
	g++ -std=c++11 -c Md5HashedPayload.cpp -o Md5HashedPayload.o

CacheStructure.o: CacheStructure.cpp CacheStructure.hpp Md5HashedPayload.hpp
	g++ -std=c++11 -c CacheStructure.cpp -o CacheStructure.o

clean:
	rm -rf *.o SniferEx
