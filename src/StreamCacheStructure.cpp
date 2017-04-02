#include "StreamCacheStructure.hpp"

StreamCache::StreamCache(std::size_t cacheSize): _hits(0), _misses(0), _collisionsNum(0),
            _itMap(), _cache(), _maxSize(cacheSize),
            _size(0) {}


float StreamCache::getHitRate(void) const {
    return (float)(_hits)/((float)(_hits) + _misses);
}

int StreamCache::getCollisionsNumber(void) const {
    return _collisionsNum;
}

// TODO: size increase, itMap, + counters
void StreamCache::add(struct in_addr ipSrc, struct in_addr ipDst, 
            u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
            unsigned char * payload, unsigned int payloadSize) {
    
    cacheIterType oldStream;
    TcpStream newStream(ipSrc, ipDst, tcpSport, tcpDport);
    bool isStreamExist = false;
    
    for (cacheIterType it = _cache.begin(); it != _cache.end(); ++it) {
        if (it->stream == newStream) {
            
            isStreamExist = true;
            oldStream = it;
            newStream = it->stream;
            
            break;
        }    
    }

    if (isStreamExist) {
        newStream.addPacketToStream(tcpSeq, payload, payloadSize);
        this->_cache.erase(oldStream);
        this->_cache.insert(CacheEntry(1, newStream));  
        
    } else {
        newStream.addPacketToStream(tcpSeq, payload, payloadSize);
        this->_cache.insert(CacheEntry(1, newStream));        
    }
}

std::size_t StreamCache::getSize(void) const {
    return _size;
}

void StreamCache::clear() {
    _itMap.clear();
    for (cacheIterType it = _cache.begin(); it != _cache.end(); ++it) {
        it->stream.~TcpStream();
    }
    _cache.clear();
}

StreamCache::~StreamCache() {
    for (cacheIterType it = _cache.begin(); it != _cache.end(); ++it) {
        it->stream.~TcpStream();
    }
}