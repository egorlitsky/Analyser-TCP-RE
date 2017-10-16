#include <fstream>
#include <sstream>
#include "StreamCacheStructure.hpp"

extern std::string searchType;

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
    
    if (this->findPayload(payload, payloadSize).dataOffset != -1) {
        ++hits;
    } else {
        ++misses;
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
}

StreamCache::HitData StreamCache::findPayload(const unsigned char * payload, const unsigned int payloadSize) {
    cacheIterType it;
    int streamIndex;

    for(it = cache.begin(), streamIndex = 0; it != cache.end(); ++it, ++streamIndex) {

        std::size_t streamSize = it->stream.streamData.size();
        int offset = -1;

        if (searchType == SEARCH_CUSTOM_STR_STR) {

            try {
                offset = custom_str_str((unsigned char*) it->stream.streamData.c_str(), payload, streamSize);
            } catch (...) {
                std::cout << "[ERROR] Exception during findSubstring() execution";
            }

            if (offset != -1) {
                return HitData(streamIndex, offset, streamSize);
            }
        }

        if (searchType == SEARCH_FIND) {
            std::string packet((char*)payload);
            offset = it->stream.streamData.find(packet);

            if (offset != std::string::npos) {
                return HitData(streamIndex, offset, streamSize);
            }
        }
        
        if (searchType == SEARCH_BOYER_MOORE) {
            std::string packet((char*)payload);
            offset = boyer_moore(it->stream.streamData, packet);

            if (offset != -1) {
                return HitData(streamIndex, offset, streamSize);
            }
        }

        if (searchType == SEARCH_KMP) {
            std::string packet((char*)payload);
            offset = knuth_morris_pratt(it->stream.streamData, packet);

            if (offset != -1) {
                return HitData(streamIndex, offset, streamSize);
            }
        }
    }
    
    return HitData(-1, -1, 0);
}

void StreamCache::printCacheData(void) {
    for(cacheIterType it = cache.begin(); it != cache.end(); ++it) {
        const char *aux       = inet_ntoa(it->stream.ipSrc);
        char       *tempSrcIp = new char[strlen(aux)+1];
        const char *ipSrc     = strcpy(tempSrcIp, aux);

        aux = inet_ntoa(it->stream.ipDst);
        char       *tempDstIp = new char[strlen(aux)+1];
        const char *ipDst     = strcpy(tempDstIp, aux);

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

        delete[] tempSrcIp;
        delete[] tempDstIp;
    }
}

std::size_t StreamCache::getSize(void) const {
    return size;
}

void StreamCache::clear() {
    cache.clear();
}

StreamCache::~StreamCache() {
    cache.clear();
}