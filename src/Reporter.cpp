#include "Reporter.hpp"
#include <iostream>


Reporter::Reporter(long long mx): barLength(0), packetNumber(0),
                                  maxPacketNumber(mx <= 0 ? 0 : mx) {}



void Reporter::inc() {
    packetNumber++;

    if (maxPacketNumber == 0) {
        if (packetNumber % pointStep == 0) {
            if (barLength++ == maxBarLength) {
                barLength = 1;
                std::cout << "\r                                                  \r"
                          << std::flush;
            }
            std::cout<< "." << std::flush;
        }
    } else {
        int currPer = (packetNumber * 100) / maxPacketNumber;
        int prevPer = ((packetNumber - 1) * 100) / maxPacketNumber;
        if (currPer > prevPer) {
            std::cout << "Progress: " << std::max(100, currPer) << "%    "
                      << std::flush;
        }
    }
}


void Reporter::fin() {
    std::cout << "\rCapturing completed                               "
              << std::endl;
}