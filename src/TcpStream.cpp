#include <arpa/inet.h>
#include "TcpStream.hpp"

extern size_t streamSize;

TcpStream::TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport)
{
    this->ipSrc = ipSrc;
    this->ipDst = ipDst;

    this->tcpSport = tcpSport;
    this->tcpDport = tcpDport;
    
    this->_size = 0;

    this->streamData = "";
}

TcpStream &TcpStream::operator=(TcpStream const& anotherTcpStream) {
    this->ipSrc = anotherTcpStream.ipSrc;
    this->ipDst = anotherTcpStream.ipDst;
    
    this->tcpSport = anotherTcpStream.tcpSport;
    this->tcpDport = anotherTcpStream.tcpDport;
    
    this->_size = anotherTcpStream.getSize();
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

std::map<u_int, std::string> TcpStream::getPackets() {
    return this->packets;
}

void TcpStream::addPacketToStream(u_int tcpSeq, const unsigned char *payload,
        const unsigned int req_size) {

    if (streamSize >= req_size + _size) {
        std::string payload_str = "";
        for (int i = 0; i < req_size; ++i) {
            payload_str += payload[i];
        }
        
        this->packets.insert (std::pair<u_int, std::string>(tcpSeq, payload_str));
        this->_size += req_size;

        this->streamData.clear();
        for(auto packet : this->packets) {
            this->streamData += packet.second;
        }
    } else {
        return;
        //std::cout << "[WARN] TCP stream is full!" << std::endl;
    }
}

std::size_t TcpStream::getSize(void) const {
    return _size;
}

std::map<u_int, std::string>::iterator TcpStream::get_first_packet() {
    return this->packets.begin();
}

TcpStream::~TcpStream() {
    typedef std::map<u_int, std::string>::iterator iter_type;

    for (iter_type packet_iter = packets.begin(); packet_iter != packets.end(); packet_iter++) {
        packet_iter->second.clear();
        packet_iter->second.shrink_to_fit();
        packets.erase(packet_iter); 
    }
    packets.clear();
    streamData.clear();
}