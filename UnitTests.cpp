#include <iostream>
#include <gtest/gtest.h>
#include "NetSniffer.hpp"


class TestNetSniffer : public ::testing::Test {
protected:
    NetSniffer *snf;
    void SetUp() {
        snf = new NetSniffer("5timesStackoverflow.pcap",
                                         256);
        std::string filt = "tcp port 80 and dst host 192.168.1.9 and ";
        filt += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
        snf->setFilter(filt);
    }
    void TearDown() {
        delete snf;
    }
};


TEST_F(TestNetSniffer, testCache) {
    snf->setLoop(512);
    ASSERT_EQ(snf->getHitRatePersent(), 13);
}


int main(int argc, char *argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}