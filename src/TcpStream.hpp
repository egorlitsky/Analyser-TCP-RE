#ifndef TCPSTREAM_HPP
#define TCPSTREAM_HPP

#include <arpa/inet.h>
#include <iostream>
#include <map>
#include "Md5HashedPayload.hpp"

// TODO: replace unsigned char* to Md5HashedPayload*
class TcpStream {
private:
    // size in bytes
    std::size_t _size;
	
public:
    struct in_addr ipSrc;
    struct in_addr ipDst;

    u_short	tcpSport;
    u_short	tcpDport;
	
    std::map<u_int, std::vector<unsigned char>> packets;
    
    TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport);
    ~TcpStream();
  
    TcpStream &operator=(TcpStream const &anotherTcpStream);
    bool operator==(TcpStream const &otherTcpStream) const;
    bool operator<(TcpStream const & otherStream) const;
    
    std::size_t getSize(void) const;
    std::map<u_int, std::vector<unsigned char>> getPackets();
    std::map<u_int, std::vector<unsigned char>>::iterator get_first_packet();
    void addPacketToStream(u_int tcpSeq, unsigned char*,
            unsigned int size);
};

#endif
