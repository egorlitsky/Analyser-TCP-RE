#ifndef CACHE_STRUCTURE_HPP
#define CACHE_STRUCTURE_HPP


#include <set>
#include <unordered_map>
#include <utility>
#include "ICache.hpp"
#include "TcpStream.hpp"


class Cache : public ICache {
private:
    int _hits;
    int _misses;
    int _collisionsNum;
    
    // sizes in bytes
    std::size_t _maxSize;
    std::size_t _size;

    struct CacheEntry {
        int freq;
        Md5HashedPayload *payload;

        CacheEntry(int f, Md5HashedPayload *pl): freq(f), payload(pl) {}
        bool operator<(CacheEntry const & a) const {
            return freq < a.freq || freq == a.freq && payload < a.payload;
        }
    };

    typedef std::set<CacheEntry>::iterator cacheIterType;

    std::set<CacheEntry> _cache;
    // TODO: think about multiset to resolve collisions
    std::unordered_map <size_t, cacheIterType> _itMap;

public:
    explicit Cache(std::size_t cacheSize);
    void printCacheData(void);
    void printStreamInfo(void);
    std::size_t getSize(void) const;
    float getHitRate(void) const;
    int getCollisionsNumber(void) const;
    void add(Md5HashedPayload const &hPayload);
    void add(struct in_addr ipSrc, struct in_addr ipDst, 
        u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
        unsigned char * payload, unsigned int payloadSize);
    void clear();
    ~Cache();
};


#endif