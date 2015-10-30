#include <iostream>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


#define DEV_NAME "wlan0"
#define NUMBER_OF_PACKAGES 512
#define PROMICIOUS_MODE false
#define TIMEOUT_MS 100
#define CACHE_SIZE 256


int main() {
    try {
        NetSniffer *snf = new NetSniffer(DEV_NAME,
                                         PROMICIOUS_MODE,
                                         TIMEOUT_MS,
                                         CACHE_SIZE);
        std::cout <<"Your IP address: " << snf->getIpAddress() << std::endl;

        std::string filterText = "tcp port 80 and dst host " 
            + snf->getIpAddress() + " and ";
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        snf->setFilter(filterText);
        snf->setLoop(NUMBER_OF_PACKAGES);
    } catch (PcapException &e) {
        std::cout << e.what();
    }

    return 0;
}
