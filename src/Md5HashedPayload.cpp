#include <openssl/md5.h>
#include "Md5HashedPayload.hpp"

// #include <ctime>
// #include <iostream>
// #include <sys/time.h>



Md5HashedPayload::Md5HashedPayload(unsigned char const *payload, 
                                   unsigned int size, bool isTemp)
{
    // struct timeval tv1, tv2;
    // gettimeofday(&tv1, NULL);

    _payloadSize = size;
    _isTemp = isTemp;

    if (!_isTemp) {
        unsigned char *copyPayload = new unsigned char[size];
        for (unsigned int i = 0; i < size; ++i) {
            copyPayload[i] = payload[i];
        }
        _payload = copyPayload;
    } else {
        _payload = payload;
    }

    _hashValue = new unsigned char[MD5_DIGEST_LENGTH];
    MD5(_payload, (long)_payloadSize, _hashValue);

    // gettimeofday(&tv2, NULL);
    // unsigned long d = 1000000UL * (tv2.tv_sec - tv1.tv_sec);
    // d += (tv2.tv_usec - tv1.tv_usec);
    // std::cout << "Time to pack this packet, in mks: " << d << std::endl;
}

/*
Md5HashedPayload::Md5HashedPayload(std::vector<unsigned char> &v,
                                   bool isTemp)
{
    _payloadSize = v.size();
    _is_temp = isTemp;
    // ...
}
*/

Md5HashedPayload::Md5HashedPayload(Md5HashedPayload const &HashedPayload) {
    unsigned int size = HashedPayload._payloadSize;
    _isTemp = false;
    _payloadSize = size;

    unsigned char *copyPayload = new unsigned char[size];
    for (unsigned int i = 0; i < size; ++i) {
        copyPayload[i] = HashedPayload._payload[i];
    }
    _payload = copyPayload;

    _hashValue = new unsigned char[MD5_DIGEST_LENGTH];
    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        _hashValue[i] = HashedPayload._hashValue[i];
    }
}


Md5HashedPayload::~Md5HashedPayload() {
    delete [] _hashValue;

    if (!_isTemp) {
        delete [] _payload;
    }
}


Md5HashedPayload &Md5HashedPayload::operator=(
        Md5HashedPayload const &HashedPayload) {
    if (this != &HashedPayload) {
        Md5HashedPayload(HashedPayload).swap(*this);
    }
    return (*this);
}


bool Md5HashedPayload::operator==(Md5HashedPayload const& otherPayload) const {
    bool res = true;

    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        res &= _hashValue[i] == otherPayload._hashValue[i];
    }

    if (res && _payloadSize == otherPayload._payloadSize) {
        unsigned int size = _payloadSize;

        for (unsigned int i = 0; i < size; ++i) {
            res &= _payload[i] == otherPayload._payload[i];
        }
    } else {
        return false;
    }

    return res;
}


bool Md5HashedPayload::swap(Md5HashedPayload &otherPayload) {
    if (_isTemp || otherPayload._isTemp) {
        return false;
    }

    std::swap(_payloadSize, otherPayload._payloadSize);
    std::swap(_payload, otherPayload._payload);
    std::swap(_hashValue, otherPayload._hashValue);

    return true;
}


std::size_t Md5HashedPayload::getHashKey(void) const {
    std::size_t res = 0;

    // 18446744069414584321 == 2**64 - 2**32 + 1
    std::size_t mod = 18446744069414584321U;

    // 4294967291 == 2**32 - 5
    std::size_t multipl = 4294967291U;

    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; i += 4U) {
        std::size_t addit = (size_t)_hashValue[i];
        addit += (std::size_t)_hashValue[i + 1] << 8;
        addit += (std::size_t)_hashValue[i + 2] << 16;
        addit += (std::size_t)_hashValue[i + 3] << 24;

        // res = (O(2**64) + O(2**32) * O(2**32)) % O(2**64)
        res = (res + addit * multipl) % mod;
    }

    return res;
}


std::size_t Md5HashedPayload::getSize(void) const {
    return _payloadSize;
}