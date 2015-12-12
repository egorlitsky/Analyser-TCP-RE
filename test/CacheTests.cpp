#include "CacheTests.hpp"
#include <iostream>

void testCacheFromFile::SetUp() {
    snf = new NetSniffer("./captures/5timesStackoverflow.pcap", &cache);
    filterText = "tcp and dst host 192.168.1.9 and ";
    filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
    snf->setFilter(filterText);
}
void testCacheFromFile::TearDown() {
    delete snf;
}


TEST_F(testTinyCache, replacePacket) {
    std::size_t size = testTinyCache::cacheSize;
    std::vector<unsigned char> val1(size / 2, 0);
    val1[1] = 1U;
    val1[2] = 2U;
    val1[3] = 2U;
    cache.add(Md5HashedPayload(val1));
    cache.add(Md5HashedPayload(val1));

    std::vector<unsigned char> val2(size / 4, 0);
    val2[1] = 2U;
    val2[2] = 3U;
    val2[3] = 3U;
    cache.add(Md5HashedPayload(val2));

    std::vector<unsigned char> val3(size / 4, 0);
    val3[1] = 3U;
    val3[2] = 4U;
    val3[3] = 4U;
    cache.add(Md5HashedPayload(val3));

    ASSERT_EQ(size, cache.getSize());

    std::vector<unsigned char> val4(size / 4 + 1, 0);
    val4[1] = 4U;
    val4[2] = 5U;
    val4[3] = 5U;
    cache.add(Md5HashedPayload(val4));

    ASSERT_EQ(size/2 + size/4 + 1, cache.getSize());
}


TEST_F(testSmallCache, samePacket) {
    unsigned char packetNumber = 128;
    std::vector<unsigned char> val(128, 1);

    for (unsigned char i = 0; i < packetNumber; ++i) {
        cache.add(Md5HashedPayload(val));
    }

    float n = packetNumber;
    ASSERT_FLOAT_EQ((n - 1)/n, cache.getHitRate());
    ASSERT_EQ(128, cache.getSize());
}


TEST_F(testSmallCache, diffPackets) {
    unsigned char packetNumber = 128;
    std::vector<unsigned char> nextVal(128, 1);

    for (unsigned char i = 1U; i <= packetNumber; ++i) {
        nextVal[63] = i * 2U;
        cache.add(Md5HashedPayload(nextVal));
    }
    ASSERT_FLOAT_EQ(0.0, cache.getHitRate());
    ASSERT_EQ(128 * packetNumber, cache.getSize());
}


TEST_F(testSmallCache, repeatedDiffPackets) {
    unsigned char packetNumber = 128;

    std::vector<unsigned char> nextVal(128, 0);
    for (size_t i = 0; i < packetNumber; ++i) {
        for (std::size_t p = 0; p < 128; ++p) {
            nextVal[p] = std::rand() % 256U;
        }

        cache.add(Md5HashedPayload(nextVal));
        cache.add(Md5HashedPayload(nextVal));
    }

    ASSERT_FLOAT_EQ(1.0/2, cache.getHitRate());
    ASSERT_EQ(128 * packetNumber, cache.getSize());
}


TEST_F(testCacheFromFile, twoTimesSameStream) {
    snf->captureAll(NULL);
    float firstHitRate = cache.getHitRate();

    Cache cache2(cacheSize);
    NetSniffer *snf2 = new NetSniffer("./captures/5timesStackoverflow.pcap",
                                      &cache2);
    snf2->setFilter(filterText);
    snf2->captureAll(NULL);
    float secHitRate = cache2.getHitRate();

    ASSERT_FLOAT_EQ(firstHitRate, secHitRate);

    delete snf2;
}