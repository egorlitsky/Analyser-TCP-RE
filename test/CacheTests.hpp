#include <gtest/gtest.h>
#include "src/NetSniffer.hpp"


class testSmallCache : public ::testing::Test {
protected:
    const std::size_t cacheSize = 128 * 1024;
    Cache cache = Cache(cacheSize);
};


class testTinyCache : public ::testing::Test {
protected:
    const std::size_t cacheSize = 128;
    Cache cache = Cache(cacheSize);
};


class testCacheFromFile : public ::testing::Test {
protected:
    const std::size_t cacheSize = 256 * 1024;
    std::string filterText;
    NetSniffer *snf;
    Cache cache = Cache(cacheSize);
    void SetUp();
    void TearDown();
};