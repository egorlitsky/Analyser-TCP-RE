#ifndef CACHE_STRUCTURE_HPP
#define CACHE_STRUCTURE_HPP


#include <set>
#include <unordered_map>
#include <utility>
#include "Md5HashedPayload.hpp"


class Cache {
private:
    int hits_;
    int misses_;
    std::size_t maxSize_;
    std::size_t size_;

    struct CacheEntry {
        int freq;
        Md5HashedPayload *payload;

        CacheEntry(int f, Md5HashedPayload *pl): freq(f), payload(pl) {}
        bool operator<(CacheEntry const & a) const {
            return freq < a.freq || freq == a.freq && payload < a.payload;
        }
    };

    typedef std::set<CacheEntry>::iterator cacheIterType;

    std::set<CacheEntry> cache_;
    // TODO: think about multiset to resolve collisions
    std::unordered_map <size_t, cacheIterType> itMap_;

public:
    explicit Cache(size_t cacheSize);
    float getHitRate(void) const;
    void add(Md5HashedPayload const &hPayload);
    void clear();
    ~Cache();
};


#endif