#include <gtest/gtest.h>
#include "src/NetSniffer.hpp"


class testSmallCache : public ::testing::Test {
protected:
    static const std::int64_t cacheSize = 128 * 1024;
    Cache *cache;
    void SetUp();
    void TearDown();
};


class testTinyCache : public ::testing::Test {
protected:
    static const std::int64_t cacheSize = 128;
    Cache *cache;
    void SetUp();
    void TearDown();
};


class testCacheFromFile : public ::testing::Test {
protected:
    static const std::int64_t cacheSize = 256 * 1024;
    std::string filterText;
    NetSniffer *snf;
    Cache *cache;
    void SetUp();
    void TearDown();
};