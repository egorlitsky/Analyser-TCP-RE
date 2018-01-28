#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include "TcpStream.hpp"

extern size_t streamSize;
extern int    chunkSize;
extern int    fileStreamsAmount;

TcpStream::TcpStream(struct in_addr ipSrc, struct in_addr ipDst, 
                     u_short tcpSport, u_short	tcpDport, bool isFile)
{
    this->ipSrc = ipSrc;
    this->ipDst = ipDst;

    this->tcpSport = tcpSport;
    this->tcpDport = tcpDport;
    
    this->_size  = 0;

    this->isBusy = false;
    this->isFile = isFile;

    this->streamData = "";
    
    if (this->isFile) {
        const char *aux       = inet_ntoa(this->ipSrc);
        char       *tempSrcIp = new char[strlen(aux)+1];
        const char *ipSrc     = strcpy(tempSrcIp, aux);

        aux                   = inet_ntoa(this->ipDst);
        char       *tempDstIp = new char[strlen(aux)+1];
        const char *ipDst     = strcpy(tempDstIp, aux);
        
        std::ostringstream oss;
        oss << "" << ipSrc << "_" << ipDst << "_" << 
                this->tcpSport << "_" << this->tcpDport;

        this->fileName = oss.str();  
        
        struct stat buf;
        if (!stat(this->fileName.c_str(), &buf) != -1) {
            std::fstream streamFile(this->fileName, std::ios::binary);
            streamFile.close();
        }
        
        delete[] tempSrcIp;
        delete[] tempDstIp;
    }
}

TcpStream &TcpStream::operator=(TcpStream const& anotherTcpStream) {
    this->ipSrc    = anotherTcpStream.ipSrc;
    this->ipDst    = anotherTcpStream.ipDst;
    
    this->tcpSport = anotherTcpStream.tcpSport;
    this->tcpDport = anotherTcpStream.tcpDport;
    
    this->_size    = anotherTcpStream.getSize();
    this->packets  = anotherTcpStream.packets;
    this->isFile   = anotherTcpStream.isFile;
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

std::string TcpStream::getStreamData() {
    if (this->isFile) {
        std::string streamData = "";
        std::ifstream inFile;
        inFile.open(this->fileName, std::ifstream::in | std::ifstream::binary);

        if (inFile.fail()) {
            std::cout << "File Stream " << this->fileName << " has been removed, exiting..."
                    << std::endl;
            return streamData;
        }
        
        std::stringstream strStream;
        strStream << inFile.rdbuf();
        std::string readed = strStream.str();
        
        for(auto filePacket : this->filePackets) {

            try {
                // first packet of file
                if (filePacket.second.first == -1) {
                    streamData += readed.substr(0, filePacket.second.second);
                } else {
                    streamData += readed.substr(filePacket.second.first, filePacket.second.second);
                }
            } catch (...) {
                std::cout << "Exception during read from file! Offset: " << filePacket.second.first << ", size:" <<
                        filePacket.second.second << ", total size: " << readed.length() << std::endl;
            }
        }

        inFile.close();
        return streamData;
        
    } else {
        return this->streamData;
    }
}

int TcpStream::addPacketToStream(u_int tcpSeq, const unsigned char *payload,
        const unsigned int req_size) {

    if (streamSize >= req_size + _size) {        
        if (chunkSize) {
            std::string payload_str = "";
            for (int i = 0; i < req_size; ++i) {
                payload_str += payload[i];
            }
            
            int chunkAmount = req_size / chunkSize;
            int lastChunkSize = req_size - (chunkAmount * chunkSize);
            
            for (int i = 0; i < chunkAmount; ++i) {
                std::string chunk(payload_str.substr(i * chunkSize, (i * chunkSize) + chunkSize));
                Md5HashedPayload *hashedPayload = new Md5HashedPayload((unsigned char *) chunk.c_str(), chunkSize, false);
                this->hashedPayloads.insert(std::pair<std::size_t, u_int>(hashedPayload->getHashKey(), tcpSeq));
            }

            if (lastChunkSize) {
                std::string lastChunk(payload_str.substr(chunkAmount * chunkSize, lastChunkSize));
                Md5HashedPayload *hashedPayload = new Md5HashedPayload((unsigned char *) lastChunk.c_str(), chunkSize, false);
                this->hashedPayloads.insert(std::pair<std::size_t, u_int>(hashedPayload->getHashKey(), tcpSeq));
            }
            this->_size += req_size;
            
        } else {
            std::string payload_str = "";
            for (int i = 0; i < req_size; ++i) {
                payload_str += payload[i];
            }
            
            if (this->isFile) {
                std::ifstream in(this->fileName, std::ifstream::ate | std::ifstream::binary);
                int length = in.tellg();
                std::ofstream streamFile(this->fileName, std::ios::binary | std::ios::app);
                streamFile << payload_str;
                streamFile.close();
                
                this->filePackets.insert (std::pair<u_int, std::pair<int, int>>(tcpSeq, std::pair<int, int>(length, req_size)));
                this->_size += req_size;
            } else {

                this->packets.insert (std::pair<u_int, std::string>(tcpSeq, payload_str));
                this->_size += req_size;

                this->streamData.clear();
                for(auto packet : this->packets) {
                    this->streamData += packet.second;
                }
            }
            
            return 0;
        }
    } else {
        return 1;
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