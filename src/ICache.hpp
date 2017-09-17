#ifndef ICACHE_HPP
#define ICACHE_HPP

#include "Md5HashedPayload.hpp"

class ICache {
public:
    virtual void  add(Md5HashedPayload const &hPayload)             = 0;
    
    virtual void  add(struct in_addr ipSrc, struct in_addr ipDst, 
        u_short tcpSport, u_short tcpDport, u_int tcpSeq, 
        unsigned char * payload, unsigned int payloadSize)          = 0;
    
    virtual void  printCacheData(void)                              = 0;
    
    virtual float getHitRate(void) const                            = 0;
    
    virtual int   getCollisionsNumber(void) const                   = 0;
};

#endif

