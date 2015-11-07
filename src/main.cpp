#include <iostream>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


//TODO: бывает еще, например, eth => командная строка
const char *DEV_NAME = "wlan0";
const int NUMBER_OF_PACKAGES  = 768;
const bool PROMICIOUS_MODE  = false;
const int TIMEOUT_MS  = 100;
const int CACHE_SIZE  = 256;


int main(int argc, char *argv[]) {
    try {
        NetSniffer *snf = NULL;
        std::string ipFilter;
        bool online = true;
        if (argc == 1) {
            snf = new NetSniffer(DEV_NAME, PROMICIOUS_MODE, 
                                 TIMEOUT_MS, CACHE_SIZE);
            ipFilter = "dst host " + snf->getIpAddress() + " and ";
            std::cout <<"Your IP address: " << snf->getIpAddress() << std::endl;
        } else {
            online == false;
            // 1st param - filename; 2nd - dst IP address
            snf = new NetSniffer(argv[1], CACHE_SIZE);
            if (argc >= 3) {
                ipFilter = "dst host ";
                ipFilter += argv[2]; 
                ipFilter += " and ";
            } else {
                ipFilter = "";
            }
        }

        std::string filterText = "tcp port 80 and " + ipFilter;
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        snf->setFilter(filterText);
        if (online) {
            snf->setLoop(NUMBER_OF_PACKAGES);
        } else {
            snf->captureAll();
        }
        std::cout << "Hit rate: " << snf->getHitRate() << std::endl;

        delete snf;
    } catch (PcapException &e) {
        std::cout << e.what();
    }

    return 0;
}
