#ifndef TCPSTREAM_HPP
#define TCPSTREAM_HPP

#include <arpa/inet.h>
#include <iostream>
#include <map>
#include "Md5HashedPayload.hpp"

// TODO: limit totalSize
class TcpStream {
private:
    // TODO: replace unsigned char* to Md5HashedPayload*
    std::map<u_int, std::vector<unsigned char>> packets;
	
public:
    struct in_addr ipSrc;
    struct in_addr ipDst;

    u_short	tcpSport;
    u_short	tcpDport;
	
    TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport);
    ~TcpStream();
  
    TcpStream &operator=(TcpStream const &anotherTcpStream);
    bool operator==(TcpStream const &otherTcpStream) const;
    bool operator<(TcpStream const & otherStream) const;
    
    // TODO: replace unsigned char* to Md5HashedPayload*
    std::map<u_int, std::vector<unsigned char>> getPackets();
    
    // TODO: replace unsigned char* to Md5HashedPayload*
    void addPacketToStream(u_int tcpSeq, unsigned char*,
            unsigned int size);
    
    std::map<u_int, std::vector<unsigned char>>::iterator get_first_packet();
};

#endif