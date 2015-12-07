#include <gtest/gtest.h>

long long capturedPacketNumber = 0;
bool withVlan = false;


int main(int argc, char *argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}