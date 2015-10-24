#include "CacheStructure.hpp"


bool Cache::compareByFreq(Md5HashedPayload const &a, Md5HashedPayload const &b) {
    return _cache[a].freq < _cache[b].freq;
}


void Cache::siftUpHeap(int index) {
    int par = (index + 1) / 2 - 1;

    if (par >= 0 && compareByFreq(_heap[index], _heap[par])) {
        _heap[index].swap(_heap[par]);
        updateIterators(index);
        updateIterators(par);

        siftUpHeap(par);
    }
}


void Cache::siftDownHeap(int index) {
    int size = _heap.size();
    if (index >= size) {
        return;
    }

    int left = (index + 1) * 2 - 1,
        right = (index + 1) * 2,
        upped = index;

    if (left < size && compareByFreq(_heap[left], _heap[index])) {
        upped = left;
    }

    if (right < size && compareByFreq(_heap[right], _heap[upped])) {
        upped = right;
    }

    if (upped != index) {
        _heap[upped].swap(_heap[index]);
        updateIterators(upped);
        updateIterators(index);

        siftDownHeap(upped);
    }
}


void Cache::addToHeap(Md5HashedPayload const &value) {
    _heap.push_back(value);
    updateIterators(_heap.size() - 1);

    siftUpHeap(_heap.size() - 1);
}

// TODO: make return value const?
Md5HashedPayload &Cache::getLfuPayload() {
    return _heap[0];
}


void Cache::popFromHeap() {
    _heap[0].swap(_heap[_heap.size() - 1]);
    updateIterators(0);

    delete _heap[_heap.size() - 1];
    _heap.pop_back();

    siftDownHeap(0);
}


void Cache::updateIterators(int index) {
    Md5HashedPayload const &key = _heap[index];
    _cache[key].heapPos = index;
}


Cache::Cache(size_t cacheSize): _hits(0), _misses(0), _heap(),
                                _cache(), _maxSize(cacheSize) {}


float Cache::getHitRate() const {
    return (float)(_hits)/(_hits + _misses);
}


void Cache::add(Md5HashedPayload const &newHashedPayload) {
    if (_cache.count(newHashedPayload)) {
        ++_hits;
        _cache[newHashedPayload].freq++;
        unsigned int heapPos = _cache[newHashedPayload].heapPos;
        siftDownHeap(heapPos);
        return;
    }

    ++_misses;
    bool fullCache = false;
    if (_currSize == _maxSize) {
        fullCache = true;
        Md5HashedPayload const &lfuPayload = getLfuPayload();
        _cache.erase(lfuPayload);
        popFromHeap();
    }

    _cache[newHashedPayload] = CacheEntry(1, _heap.size());
    addToHeap(newHashedPayload);

    if (!fullCache) {
        _currSize++;
    }
}


Cache::~Cache() {
    for (int i = 0; i < _heap.size(); ++i) {
        delete _heap[i];
    }
}