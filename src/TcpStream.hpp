#ifndef TCPSTREAM_HPP
#define TCPSTREAM_HPP

#include <arpa/inet.h>
#include <iostream>
#include <map>
#include "Md5HashedPayload.hpp"

class TcpStream {
private:
    std::size_t _size;
	
public:
    struct in_addr ipSrc;
    struct in_addr ipDst;

    u_short	tcpSport;
    u_short	tcpDport;
	
    std::map<u_int, std::string> packets;

    std::string streamData;
    
    std::map<std::size_t, u_int> hashedPayloads;
    
    TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport);
    ~TcpStream();
  
    TcpStream &operator=(TcpStream const &anotherTcpStream);
    bool operator==(TcpStream const &otherTcpStream) const;
    bool operator<(TcpStream const &otherStream) const;
    
    std::size_t getSize(void) const;
    std::map<u_int, std::string> getPackets();
    std::map<u_int, std::string>::iterator get_first_packet();
    void addPacketToStream(u_int tcpSeq, const unsigned char*,
            const unsigned int size);
};

#endif
