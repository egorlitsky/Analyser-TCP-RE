#ifndef CACHE_STRUCTURE_HPP
#define CACHE_STRUCTURE_HPP

#include <vector>
#include <unordered_map>
#include "Md5HashedPayload.hpp"


class Cache {
private:
    int _hits;
    int _misses;
    std::size_t _maxSize;
    std::size_t _currSize;

    struct CacheEntry {
        unsigned int freq;
        unsigned int heapPos;

        CacheEntry(unsigned int f, unsigned int hp): freq(f), heapPos(hp) {}
    };

    std::vector<Md5HashedPayload> _heap;
    std::unordered_map <Md5HashedPayload,
                        CacheEntry,
                        Md5HashedPayloadHasher> _cache;

    bool compareByFreq(Md5HashedPayload const &a, Md5HashedPayload const &b);

    void siftUpHeap(int index);
    void siftDownHeap(int index);
    void addToHeap(Md5HashedPayload const &value);

    Md5HashedPayload &getLfuPayload();
    void popFromHeap();

    void updateIterators(int index);

public:
    explicit Cache(size_t cacheSize = 128);
    float getHitRate(void) const;
    void add(Md5HashedPayload const &newHashedPayload);
    ~Cache();
};


#endif