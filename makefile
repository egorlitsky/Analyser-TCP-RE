program_name = SniferEx
lib_dep = -lpcap -lcrypto

all: $(program_name)
	

$(program_name): main.o NetSniffer.o Md5HashedPayload.o CacheStructure.o
	g++ -std=c++11 $^ $(lib_dep) -o $@

main.o: main.cpp NetSniffer.hpp
	g++ -std=c++11 -c main.cpp -o $@

NetSniffer.o: NetSniffer.cpp NetSniffer.hpp TcpIpInternetHeaders.hpp Md5HashedPayload.hpp
	g++ -std=c++11 -c NetSniffer.cpp -o $@

Md5CachedPayload.o: Md5HashedPayload.cpp Md5HashedPayload.hpp
	g++ -std=c++11 -c Md5HashedPayload.cpp -o $@

CacheStructure.o: CacheStructure.cpp CacheStructure.hpp Md5HashedPayload.hpp
	g++ -std=c++11 -c CacheStructure.cpp -o $@

clean:
	rm -rf *.o SniferEx
