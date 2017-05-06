#include <string.h>
#include <fstream>
#include <sstream>
#include "StreamCacheStructure.hpp"

StreamCache::StreamCache(std::size_t cacheSize): hits(0), misses(0), collisionsNum(0),
            cache(), maxSize(cacheSize), size(0) {}


float StreamCache::getHitRate(void) const {
    return (float)(hits)/((float)(hits) + misses);
}

int StreamCache::getCollisionsNumber(void) const {
    return collisionsNum;
}

void StreamCache::add(Md5HashedPayload const &hPayload) {
    return;
}

void StreamCache::add(struct in_addr ipSrc, struct in_addr ipDst, 
            u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
            unsigned char * payload, unsigned int payloadSize) {
    
    TcpStream newStream(ipSrc, ipDst, tcpSport, tcpDport);
    bool isStreamExist = false;
    
    if (this->findPayload(payload, payloadSize)) {
        ++hits;
    } else {
        ++misses;
    }
    
    for (cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        if (it->stream == newStream) {
            isStreamExist = true;
            it->stream.addPacketToStream(tcpSeq, payload, payloadSize);
            break;
        }    
    }

    if (!isStreamExist) {
        newStream.addPacketToStream(tcpSeq, payload, payloadSize);
        this->cache.push_back(CacheEntry(newStream));        
    }
}

bool StreamCache::findPayload(unsigned char * payload, unsigned int payloadSize) {
    for(cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        std::string streamData = "";
        std::string packet((char*)payload);
        
        for(auto packet : it->stream.packets) {
            for (int i = 0; i < packet.second.size(); ++i) {
                streamData += packet.second[i];
            }
        }
        
        std::size_t found = streamData.find(packet);
        if (found!=std::string::npos) {
            return true;
        }
            
        streamData.clear();
    }
    
    return false;
}

void StreamCache::printCacheData(void) {
    for(cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        const char *aux = inet_ntoa(it->stream.ipSrc);
        const char *ipSrc = strcpy(new char[strlen(aux)+1], aux);

        aux = inet_ntoa(it->stream.ipDst);
        const char *ipDst = strcpy(new char[strlen(aux)+1], aux);

        std::ostringstream oss;
        oss << "" << ipSrc << "_" << ipDst << "_" << 
                it->stream.tcpSport << "_" << it->stream.tcpDport << ".txt";

        std::string file_name = oss.str();   
        std::ofstream fout(file_name, std::ios::binary);

        // output like the Wireshark output in 'Follow TCP Stream'
        for(auto packet : it->stream.packets) {
            for (int i = 0; i < packet.second.size(); ++i) {

                char c = packet.second[i],
                        wiresharkChar = c >= ' ' && c < 0x7f ? c : '.';

                if (c == '\n' || c == '\r' || c == '\t') {
                    fout << c;
                } else {
                    fout << wiresharkChar;
                }
            }
        }

        fout.close();
    }
}

std::size_t StreamCache::getSize(void) const {
    return size;
}

void StreamCache::clear() {
    for (cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        it->stream.~TcpStream();
    }
    cache.clear();
}

StreamCache::~StreamCache() {
    for (cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        it->stream.~TcpStream();
    }
}