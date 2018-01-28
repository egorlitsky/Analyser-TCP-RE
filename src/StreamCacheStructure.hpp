#ifndef STREAM_CACHE_STRUCTURE_HPP
#define STREAM_CACHE_STRUCTURE_HPP


#define SEARCH_FIND           "find"
#define SEARCH_CUSTOM_STR_STR "custom_str_str"
#define SEARCH_BOYER_MOORE    "boyer_moore"
#define SEARCH_KMP            "knuth_morris_pratt"

#include <utility>
#include <string>
#include "TcpStream.hpp"
#include "ICache.hpp"
#include "SubStringUtils.hpp"

class StreamCache : public ICache {
private:
    int hits;
    int misses;
    int collisionsNum;
    
    // sizes in bytes
    std::size_t maxSize;
    std::size_t size;
    
    struct CacheEntry {
        int freq;
        TcpStream stream;
        CacheEntry(int frequency, TcpStream &tcpStream): freq(frequency), stream(tcpStream) {}
        bool operator<(CacheEntry const & a) const {
            return freq < a.freq;
        }
    };
    
    struct HitData {
        int streamIndex;
        int dataOffset;
        std::size_t dataSize;
        HitData(int index, int offset, std::size_t size):
            streamIndex(index), dataOffset(offset), dataSize(size) {}
        void operator =(HitData& b) {
            this->dataOffset  = b.dataOffset;
            this->dataSize    = b.dataSize;
            this->streamIndex = b.streamIndex;
        }
    };

    std::vector<CacheEntry> cache;
    
    typedef std::vector<CacheEntry>::iterator cacheIterType;
    
    std::pair <int, int> searchResult; 

public:
    explicit StreamCache(std::size_t cacheSize);
    
    void printCacheData(void);
    
    void printStreamInfo(void);

    std::size_t getSize(void) const;
    
    float getHitRate(void) const;
    
    int getCollisionsNumber(void) const;
    
    void add(Md5HashedPayload const &hPayload);
    
    void add(struct in_addr ipSrc, struct in_addr ipDst, 
        u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
        unsigned char * payload, unsigned int payloadSize);
    
    HitData findPayload(const unsigned char * payload, const unsigned int payloadSize);
    
    void runThread(int threadId, const unsigned char * payload);
    
    void clear();
    
    ~StreamCache();
};


#endif