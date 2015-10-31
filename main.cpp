#include <iostream>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


#define DEV_NAME "wlan0"
#define NUMBER_OF_PACKAGES 512
#define PROMICIOUS_MODE false
#define TIMEOUT_MS 100
#define CACHE_SIZE 256


int main(int argc, char *argv[]) {
    try {
        NetSniffer *snf = NULL;
        std::string ipAddr;
        if (argc == 1) {
            snf = new NetSniffer(DEV_NAME, PROMICIOUS_MODE, 
                                 TIMEOUT_MS, CACHE_SIZE);
            ipAddr = snf->getIpAddress();
            std::cout <<"Your IP address: " << ipAddr << std::endl;
        } else {
            // 1st param - filemane; 2nd - dst IP address
            snf = new NetSniffer(argv[1], CACHE_SIZE);
            ipAddr = argv[2];
        }

        std::string filterText = "tcp port 80 and dst host " + ipAddr + " and ";
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        snf->setFilter(filterText);
        snf->setLoop(NUMBER_OF_PACKAGES);
        std::cout << "Hit rate: " << snf->getHitRatePersent() <<"%" << std::endl;

        delete snf;
    } catch (PcapException &e) {
        std::cout << e.what();
    }

    return 0;
}
