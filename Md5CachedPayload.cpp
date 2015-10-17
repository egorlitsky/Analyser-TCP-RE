#include "Md5CachedPayload.hpp"


Md5CachedPayload::Md5CachedPayload(unsigned char const *payload, 
                                   unsigned int size)
{
    _payloadSize = size;
    _payload = new unsigned char[size];
    for (unsigned int i = 0; i < size; ++i) {
        _payload[i] = payload[i];
    }

    _cacheValue = new unsigned char[MD5_DIGEST_LENGTH];
    MD5(_payload, (long)_payloadSize, _cacheValue);
}


Md5CachedPayload::Md5CachedPayload(Md5CachedPayload const &CachedPayload) {
    unsigned int size = CachedPayload._payloadSize;
    _payloadSize = size;
    _payload = new unsigned char[size];
    for (unsigned int i = 0; i < size; ++i) {
        _payload[i] = CachedPayload._payload[i];
    }

    _cacheValue = new unsigned char[MD5_DIGEST_LENGTH];
    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        _cacheValue[i] = CachedPayload._cacheValue[i];
    }
}


Md5CachedPayload::~Md5CachedPayload() {
    delete [] _payload;
    delete [] _cacheValue;
}
