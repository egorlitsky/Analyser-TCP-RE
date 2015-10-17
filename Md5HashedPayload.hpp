#ifndef MD5HASHEDPAYLOAD_HPP
#define MD5HASHEDPAYLOAD_HPP

#include <openssl/md5.h>

class Md5CachedPayload {
protected:
    unsigned int _payloadSize;
    unsigned char *_payload;
    unsigned char *_cacheValue;

public:
    Md5CachedPayload(unsigned char const *payload, unsigned int size);
    Md5CachedPayload(Md5CachedPayload const &CachedPayload);
    ~Md5CachedPayload();

    Md5CachedPayload &operator=(Md5CachedPayload const &CachedPayload) {
        if (this != &CachedPayload) {
            delete [] _payload;
            delete [] _cacheValue;

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
        return (*this);
    }
};


#endif
