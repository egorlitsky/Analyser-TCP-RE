#include "CacheTests.hpp"
#include <iostream>
#include <cstdint>


void testSmallCache::SetUp() {
    cache = new Cache(cacheSize);
}
void testSmallCache::TearDown() {
    delete cache;
}

void testTinyCache::SetUp() {
    cache = new Cache(cacheSize);
}
void testTinyCache::TearDown() {
    delete cache;
}

void testCacheFromFile::SetUp() {
    cache = new Cache(cacheSize);
    snf = new NetSniffer("./captures/5timesStackoverflow.pcap", cache);
    filterText = "tcp port 80 and dst host 192.168.1.9 and ";
    filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
    snf->setFilter(filterText);
}
void testCacheFromFile::TearDown() {
    delete snf;
    delete cache;
}


TEST_F(testTinyCache, replacePacket) {
    std::int64_t size = testTinyCache::cacheSize;
    unsigned char *val1 = new unsigned char[size / 2];
    val1[1] = 1U;
    val1[2] = 2U;
    val1[3] = 2U;
    cache->add(Md5HashedPayload(val1, size / 2));
    cache->add(Md5HashedPayload(val1, size / 2));

    unsigned char *val2 = new unsigned char[size / 4];
    val2[1] = 2U;
    val2[2] = 3U;
    val2[3] = 3U;
    cache->add(Md5HashedPayload(val2, size / 4));

    unsigned char *val3 = new unsigned char[size / 4];
    val3[1] = 3U;
    val3[2] = 4U;
    val3[3] = 4U;
    cache->add(Md5HashedPayload(val3, size / 4));

    ASSERT_EQ(size, cache->getSize());

    unsigned char *val4 = new unsigned char[size / 4 + 1];
    val4[1] = 4U;
    val4[2] = 5U;
    val4[3] = 5U;
    cache->add(Md5HashedPayload(val4, size / 4 + 1));

    ASSERT_EQ(size/2 + size/4 + 1, cache->getSize());

    delete val1;
    delete val2;
    delete val3;
    delete val4;
}


TEST_F(testSmallCache, samePacket) {
    unsigned char packetNumber = 128;
    for (unsigned char i = 0; i < packetNumber; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        for (std::size_t p = 0; p < 128; ++p) {
            nextVal[p] = 1U;
        }

        cache->add(Md5HashedPayload(nextVal, 128));
        delete [] nextVal;
    }
    float n = packetNumber;
    ASSERT_FLOAT_EQ((n - 1)/n, cache->getHitRate());
    ASSERT_EQ(128, cache->getSize());
}


TEST_F(testSmallCache, diffPackets) {
    unsigned char packetNumber = 128;
    for (unsigned char i = 1U; i <= packetNumber; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        for (size_t p = 0; p < 128; ++p) {
            nextVal[p] = 1U;
        }
        nextVal[63] = i * 2U;

        cache->add(Md5HashedPayload(nextVal, 128));
        delete [] nextVal;
    }
    ASSERT_FLOAT_EQ(0.0, cache->getHitRate());
    ASSERT_EQ(128 * packetNumber, cache->getSize());
}


TEST_F(testSmallCache, repeatedDiffPackets) {
    unsigned char packetNumber = 128;
    unsigned char *values[packetNumber];

    for (size_t i = 0; i < packetNumber; ++i) {
        unsigned char *nextVal = new unsigned char[128];
        values[i] = nextVal;
        for (std::size_t p = 0; p < 128; ++p) {
            nextVal[p] = std::rand() % 256U;
        }

        cache->add(Md5HashedPayload(nextVal, 128));
    }
    
    for (size_t i = 0; i < packetNumber; ++i) {
        cache->add(Md5HashedPayload(values[i], 128));
        delete [] values[i];
    }

    ASSERT_FLOAT_EQ(1.0/2, cache->getHitRate());
    ASSERT_EQ(128 * packetNumber, cache->getSize());
}


TEST_F(testCacheFromFile, twoTimesSameStream) {
    snf->captureAll();
    float firstHitRate = cache->getHitRate();

    Cache *cache2 = new Cache(cacheSize);
    NetSniffer *snf2 = new NetSniffer("./captures/5timesStackoverflow.pcap",
                                      cache2);
    snf2->setFilter(filterText);
    snf2->captureAll();
    float secHitRate = cache2->getHitRate();

    ASSERT_FLOAT_EQ(firstHitRate, secHitRate);

    delete snf2;
    delete cache2;
}