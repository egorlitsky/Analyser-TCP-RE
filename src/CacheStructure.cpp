#include "CacheStructure.hpp"

Cache::Cache(std::int64_t cacheSize): hits_(0), misses_(0), itMap_(),
                                cache_(), maxSize_(cacheSize), size_(0) {}


float Cache::getHitRate() const {
    return (float)(hits_)/((float)(hits_) + misses_);
}


void Cache::add(Md5HashedPayload const &hPayload) {
    std::size_t hashKey = hPayload.getHashKey();

    if (itMap_.count(hashKey)) {
        cacheIterType cacheIter = itMap_[hashKey];
        int freq = cacheIter->freq;
        Md5HashedPayload *payload = cacheIter->payload;

        if (hPayload == *payload) {
            ++hits_;
            cache_.erase(itMap_[hashKey]);
            cacheIterType iter = cache_.insert(
                CacheEntry(freq + 1, payload)).first;
            itMap_[hashKey] = iter;
        } else {
            ++misses_;
        }
        return;
    }

    ++misses_;
    Md5HashedPayload *newPayload = new Md5HashedPayload(hPayload);
    std::int64_t requiredSize = newPayload->getSize();
    while (maxSize_ - size_ < requiredSize) {
        cacheIterType iterToLfuElement = cache_.begin();
        Md5HashedPayload *lfuPayload = iterToLfuElement->payload;

        size_ -= lfuPayload->getSize();
        itMap_.erase(lfuPayload->getHashKey());
        delete lfuPayload;
        cache_.erase(iterToLfuElement);
    }

    cacheIterType iter = cache_.insert(CacheEntry(1, newPayload)).first;
    itMap_[newPayload->getHashKey()] = iter;
    size_ += requiredSize;
}

std::int64_t Cache::getSize(void) const {
    return size_;
}


void Cache::clear() {
    itMap_.clear();
    for (cacheIterType it = cache_.begin(); it != cache_.end(); ++it) {
        delete it->payload;
    }
    cache_.clear();
}


Cache::~Cache() {
    // itMap_.clear();
    for (cacheIterType it = cache_.begin(); it != cache_.end(); ++it) {
        delete it->payload;
    }
}