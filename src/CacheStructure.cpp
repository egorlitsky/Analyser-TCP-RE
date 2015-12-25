#include "CacheStructure.hpp"

Cache::Cache(std::size_t cacheSize): _hits(0), _misses(0), _collisionsNum(0),
                                _itMap(), _cache(), _maxSize(cacheSize),
                                _size(0) {}


float Cache::getHitRate(void) const {
    return (float)(_hits)/((float)(_hits) + _misses);
}

int Cache::getCollisionsNumber(void) const {
    return _collisionsNum;
}


void Cache::add(Md5HashedPayload const &hPayload) {
    std::size_t hashKey = hPayload.getHashKey();

    if (_itMap.count(hashKey)) {
        cacheIterType cacheIter = _itMap[hashKey];
        int freq = cacheIter->freq;
        Md5HashedPayload *payload = cacheIter->payload;

        if (hPayload == *payload) {
            ++_hits;
            _cache.erase(_itMap[hashKey]);
            cacheIterType iter = _cache.insert(
                CacheEntry(freq + 1, payload)
            ).first;
            _itMap[hashKey] = iter;
        } else {
            ++_misses;
            ++_collisionsNum;
        }
        return;
    }

    ++_misses;
    Md5HashedPayload *newPayload = new Md5HashedPayload(hPayload);
    std::size_t requiredSize = newPayload->getSize();
    if (_maxSize < requiredSize) {
        return;
    }
    while (_maxSize < requiredSize + _size) {
        cacheIterType iterToLfuElement = _cache.begin();
        Md5HashedPayload *lfuPayload = iterToLfuElement->payload;

        _size -= lfuPayload->getSize();
        _itMap.erase(lfuPayload->getHashKey());
        delete lfuPayload;
        _cache.erase(iterToLfuElement);
    }

    cacheIterType iter = _cache.insert(CacheEntry(1, newPayload)).first;
    _itMap[newPayload->getHashKey()] = iter;
    _size += requiredSize;
}

std::size_t Cache::getSize(void) const {
    return _size;
}


void Cache::clear() {
    _itMap.clear();
    for (cacheIterType it = _cache.begin(); it != _cache.end(); ++it) {
        delete it->payload;
    }
    _cache.clear();
}


Cache::~Cache() {
    for (cacheIterType it = _cache.begin(); it != _cache.end(); ++it) {
        delete it->payload;
    }
}