#include "CacheTests.hpp"
#include <iostream>
#include <cstdint>


void testSmallCache::SetUp() {
    cache = new Cache(cacheSize);
}
void testSmallCache::TearDown() {
    delete cache;
}

void testCacheFromFile::SetUp() {
    snf = new NetSniffer("./captures/5timesStackoverflow.pcap", cacheSize);
    filterText = "tcp port 80 and dst host 192.168.1.9 and ";
    filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
    snf->setFilter(filterText);
}
void testCacheFromFile::TearDown() {
    delete snf;
}



TEST_F(testSmallCache, samePacket) {
    for (unsigned char i = 0; i < testSmallCache::cacheSize; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        for (size_t p = 0; p < 128; ++p) {
            nextVal[p] = 1U;
        }
        cache->add(Md5HashedPayload(nextVal, 128));

        delete [] nextVal;
    }
    float n = testSmallCache::cacheSize;
    ASSERT_FLOAT_EQ((n - 1)/n, cache->getHitRate());
}


TEST_F(testSmallCache, diffPackets) {
    for (unsigned char i = 1U; i <= testSmallCache::cacheSize; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        for (size_t p = 0; p < 128; ++p) {
            nextVal[p] = 1U;
        }
        nextVal[63] = i * 2U;

        cache->add(Md5HashedPayload(nextVal, 128));

        delete [] nextVal;
    }
    ASSERT_FLOAT_EQ(0.0, cache->getHitRate());
}


TEST_F(testSmallCache, repeatedDiffPackets) {
    unsigned char *values[testSmallCache::cacheSize];

    for (size_t i = 0; i < testSmallCache::cacheSize; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        values[i] = nextVal;
        for (size_t p = 0; p < 128; ++p) {
            nextVal[p] = std::rand() % 256U;
        }

        cache->add(Md5HashedPayload(nextVal, 128));
    }
    
    for (size_t i = 0; i < testSmallCache::cacheSize; ++i) {
        cache->add(Md5HashedPayload(values[i], 128));
        delete [] values[i];
    }

    ASSERT_FLOAT_EQ(1.0/2, cache->getHitRate());
}


TEST_F(testCacheFromFile, twoTimesSameStream) {
    snf->captureAll();
    float firstHitRate = snf->getHitRate();

    NetSniffer *snf2 = new NetSniffer("./captures/5timesStackoverflow.pcap", cacheSize);
    snf2->setFilter(filterText);
    snf2->captureAll();
    float secHitRate = snf2->getHitRate();

    ASSERT_FLOAT_EQ(firstHitRate, secHitRate);

    delete snf2;
}