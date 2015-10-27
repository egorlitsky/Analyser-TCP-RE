#ifndef MD5HASHEDPAYLOAD_HPP
#define MD5HASHEDPAYLOAD_HPP


#include <algorithm>


class Md5HashedPayload {
private:
    unsigned int _payloadSize;
    unsigned char const *_payload;
    unsigned char *_hashValue;
    bool _isTemp;

public:
    Md5HashedPayload(unsigned char const *payload, unsigned int size, 
                     bool isTemp = false);
    Md5HashedPayload(Md5HashedPayload const &HashedPayload);
    ~Md5HashedPayload();
    Md5HashedPayload &operator=(Md5HashedPayload const &HashedPayload);
    bool operator==(Md5HashedPayload const& otherPayload) const;

    // swaps only non-temporary payloads
    bool swap(Md5HashedPayload &otherPayload);

    // returns array allocated by new operator
    unsigned char *copyMd5Hash() const;

    size_t getHashKey() const;
};


#endif
