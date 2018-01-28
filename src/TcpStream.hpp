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

    // <tcpSeq, payload>
    std::map<u_int, std::string> packets;
    
    std::string fileName;
    
    // <tcpSeq, <packetPositionInFile, packetLength>>
    std::map<u_int, std::pair<int, int>> filePackets;

    std::string streamData;
    
    std::map<std::size_t, u_int> hashedPayloads;
    
    volatile bool isBusy;
    
    bool isFile;

    TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport, bool isFile);
    ~TcpStream();
  
    TcpStream &operator=(TcpStream const &anotherTcpStream);
    bool operator==(TcpStream const &otherTcpStream) const;
    bool operator<(TcpStream const &otherStream) const;
    
    std::size_t getSize(void) const;
    std::string getStreamData();
    std::map<u_int, std::string> getPackets();
    std::map<u_int, std::string>::iterator get_first_packet();
    
    // returns 0 if packet has been added, 1 if there is no space in stream
    int addPacketToStream(u_int tcpSeq, const unsigned char*,
            const unsigned int size);
};

#endif
