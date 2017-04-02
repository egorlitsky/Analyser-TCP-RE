#ifndef STREAM_CACHE_STRUCTURE_HPP
#define STREAM_CACHE_STRUCTURE_HPP


#include <set>
#include <unordered_map>
#include <utility>
#include "TcpStream.hpp"

class StreamCache {
private:
    int _hits;
    int _misses;
    int _collisionsNum;
    
    // sizes in bytes
    std::size_t _maxSize;
    std::size_t _size;

public:
    explicit StreamCache(std::size_t cacheSize);
    
    struct CacheEntry {
        int freq;
        TcpStream stream;

        CacheEntry(int f, TcpStream &tcpStream): freq(f), stream(tcpStream) {}
        bool operator<(CacheEntry const & a) const {
            return freq < a.freq || freq == a.freq && stream < a.stream;
        }
    };
    
    std::set<CacheEntry> _cache;
    
    typedef std::set<CacheEntry>::iterator cacheIterType;
    
    std::unordered_map <size_t, cacheIterType> _itMap;
    
    std::size_t getSize(void) const;
    
    float getHitRate(void) const;
    
    int getCollisionsNumber(void) const;
    
    void add(struct in_addr ipSrc, struct in_addr ipDst, 
        u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
        unsigned char * payload, unsigned int payloadSize);
    
    void clear();
    
    ~StreamCache();
    
    std::set<TcpStream> tcpStreams;
};


#endif