#include "Md5HashedPayload.hpp"
#include <openssl/md5.h>


Md5HashedPayload::Md5HashedPayload(unsigned char const *payload, 
                                   unsigned int size, bool isTemp) {
    _payloadSize = size;
    _isTemp = isTemp;

    if (!isTemp) {
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

}


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
/*
        delete [] _payload;
        delete [] _hashValue;

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
*/
        Md5HashedPayload(HashedPayload).swap(*this);
    }
    return (*this);
}


bool Md5HashedPayload::operator==(Md5HashedPayload const& otherPayload) {
    bool res = true;

    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        res &= _hashValue[i] == otherPayload._hashValue[i];
    }

    if (res && _payloadSize == otherPayload._payloadSize) {
        unsigned int size = _payloadSize;

        for (unsigned int i = 0; i < size; ++i) {
            res &= _payload[i] == otherPayload._payload[i];
        }
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


unsigned char *Md5HashedPayload::copyMd5Hash() const {
    unsigned char *copyHashValue = new unsigned char[MD5_DIGEST_LENGTH];
    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        copyHashValue[i] = _hashValue[i];
    }
    return copyHashValue;
}


size_t Md5HashedPayloadHasher::operator()(
        Md5HashedPayload const &hashedPayload) {
    size_t res = 0;
    unsigned char *md5Hash = hashedPayload.copyMd5Hash();

    // 18446744069414584321 == 2**64 - 2**32 + 1
    size_t mod = 18446744069414584321;
    // 16777213 == 2**24 - 3
    size_t multipl = 16777213;
    for (unsigned int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        res = (res + (size_t)md5Hash[i] * multipl) % mod;

    }

    delete [] md5Hash;
    return res;
}

