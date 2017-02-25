#include <arpa/inet.h>
#include "TcpStream.hpp"

TcpStream::TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport)
{
    this->ipSrc = ipSrc;
    this->ipDst = ipDst;

    this->tcpSport = tcpSport;
    this->tcpDport = tcpDport;
}

TcpStream &TcpStream::operator=(TcpStream const& anotherTcpStream) {
    this->ipSrc = anotherTcpStream.ipSrc;
    this->ipDst = anotherTcpStream.ipDst;
    
    this->tcpSport = anotherTcpStream.tcpSport;
    this->tcpDport = anotherTcpStream.tcpDport;
    
    this->packets = anotherTcpStream.packets;
}

bool TcpStream::operator==(TcpStream const& otherStream) const {
    if (this->ipSrc.s_addr == otherStream.ipSrc.s_addr &&
            this->ipDst.s_addr == otherStream.ipDst.s_addr &&
            this->tcpSport == otherStream.tcpSport &&
            this->tcpDport == otherStream.tcpDport) {

        return true;
    }
	
    return false;
}

bool TcpStream::operator<(TcpStream const & otherStream) const {
    return true;
}

// TODO: replace unsigned char* to Md5HashedPayload*
std::map<u_int, std::pair<unsigned int, unsigned char*>> TcpStream::getPackets() {
    return this->packets;
}

// TODO: replace unsigned char* to Md5HashedPayload*
void TcpStream::addPacketToStream(u_int tcpSeq, unsigned char *payload,
        unsigned int size, bool isTemp) {

    if (!isTemp) {
        unsigned char *copyPayload = new unsigned char[size];
        
        for (unsigned int i = 0; i < size; ++i) {
            copyPayload[i] = payload[i];
        }
        
        this->packets.insert (std::pair<u_int, std::pair<unsigned int, unsigned char*>>(tcpSeq, std::pair<unsigned int, unsigned char*>(size, copyPayload)));
    } else {
        this->packets.insert (std::pair<u_int, std::pair<unsigned int, unsigned char*>>(tcpSeq, std::pair<unsigned int, unsigned char*>(size, payload)));
    }
}

std::map<u_int, std::pair<unsigned int, unsigned char*>>::iterator TcpStream::get_first_packet() {
    return this->packets.begin();
}

TcpStream::~TcpStream() {
    typedef std::map<u_int, std::pair<unsigned int, unsigned char*>>::iterator iter_type;

    for (iter_type packet_iter = packets.begin(); packet_iter != packets.end(); packet_iter++) {
        packets.erase(packet_iter); 
    }
}