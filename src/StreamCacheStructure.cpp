#include <string.h>
#include <fstream>
#include <sstream>
#include "StreamCacheStructure.hpp"
#include <limits.h>

#define U_CHAR_MAX1 (UCHAR_MAX + 1)
#define NULL_SYMBOL 0x00

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

int findSubstring(const unsigned char * str1, const unsigned char * str2, size_t slen) {
    unsigned char max_len = 140;
    
    if (!*str2) {
        return -1;
    }

    unsigned char index_header_first[U_CHAR_MAX1];
    unsigned char index_header_end[U_CHAR_MAX1];
    unsigned char last_char[U_CHAR_MAX1];
    unsigned char sorted_index[U_CHAR_MAX1];

    memset(index_header_first, NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(index_header_end,   NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(last_char,          NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(sorted_index,       NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);

    unsigned char *cp2 = (unsigned char*) str2;
    unsigned char v;
    unsigned int  len = 0;
    unsigned char current_ind = 1;

    while((v =* cp2) && (len < max_len)) {
        if(index_header_first[v] == 0) {
            index_header_first[v]     = current_ind;
            index_header_end[v]       = current_ind;
            sorted_index[current_ind] = len;
        } else {
            unsigned char last_ind    = index_header_end[v];
            last_char[current_ind]    = last_ind;
            index_header_end[v]       = current_ind;
            sorted_index[current_ind] = len;
        }

        current_ind++;
        len++;
        cp2++;
    }

    if(len > slen) {
        return -1;
    }

    unsigned char *s1, *s2;
    unsigned char *cp     = (unsigned char *) str1 + (len - 1);
    unsigned char *cp_end = cp + slen;

    while (cp < cp_end) {
        unsigned char ind = *cp;
        if((ind = index_header_end[ind])) {

            do {
                unsigned char pos_in_len = sorted_index[ind];
                s1 = cp - pos_in_len;

                if((unsigned char*)s1 >= str1) {
                    s2 = (unsigned char*) str2;
                    while (*s2 && !(*s1 ^ *s2)) {
                        s1++, s2++;
                    }

                    if (!*s2) {
                        return int((unsigned char*)(cp - pos_in_len) - str1);
                    }
                }
            }
            while(ind = last_char[ind]);
        }
        cp += len;
    }
    return -1;
}

StreamCache::HitData StreamCache::findPayload(unsigned char * payload, unsigned int payloadSize) {
    cacheIterType it;
    int streamIndex;

    for(it = cache.begin(), streamIndex = 0; it != cache.end(); ++it, ++streamIndex) {

//  slow search
//        std::string packet((char*)payload);
//        if (it->stream.streamData.find(packet) != std::string::npos) {
//            return true;
//        }

        std::size_t streamSize = it->stream.streamData.size();
        int offset = -1;

        unsigned char* ptr = new unsigned char[streamSize];
        ptr = (unsigned char*) it->stream.streamData.c_str();

        try {
            offset = findSubstring(ptr, payload, streamSize);
        } catch (...) {
            std::cout << "[ERROR] Exception during findSubstring() execution";
        }
        
        if (offset != -1) {
            return HitData(streamIndex, offset, streamSize);
        }
    }
    
    return HitData(-1, -1, 0);
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