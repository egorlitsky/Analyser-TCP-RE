#include <iostream>
#include <string>
#include <vector>
#include <tclap/CmdLine.h>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


//TODO: бывает еще, например, eth => командная строка
//const char *DEV_NAME = "wlan0";
const int NUMBER_OF_PACKAGES  = 768;
const bool PROMICIOUS_MODE  = false;
const int TIMEOUT_MS  = 100;
//const int CACHE_SIZE  = 256;



int main(int argc, char **argv) {
    try {

        TCLAP::CmdLine cmd("Description message", ' ', "0.9");

        TCLAP::ValueArg<size_t> cacheSizeArg("s", "size",
                                          "Sets size of cache (in packets)",
                                          false, 256, "positive number");

        TCLAP::ValueArg<std::string> ipAddrArg(
                        "", "ip_addr", "Sets ip address of destination", false,
                        "", "4 numbers in [0..255] divided by \'.\'"
                        );

        TCLAP::ValueArg<std::string> devArg("d", "device",
                                            "Sets device to capture from",
                                            true, "wlan0", "device name");
        TCLAP::MultiArg<std::string> filenamesArg(
                            "f", "filename", "Gets pcap filenames",
                            true, "filenames"
                            );

        cmd.add(cacheSizeArg);
        cmd.add(ipAddrArg);
        cmd.xorAdd(devArg, filenamesArg);
        cmd.parse(argc, argv);


        bool isOnline = devArg.isSet();
        std::size_t cacheSize = cacheSizeArg.getValue();

        std::string ipAddr = ipAddrArg.getValue();
        std::string ipFilter = "";
        if (ipAddr != "") {
            ipFilter = "dst host " + ipAddr + " and ";
        }
        std::string filterText = "tcp port 80 and " + ipFilter;
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        NetSniffer *snf = NULL;

        if (isOnline) {
            std::string devName = devArg.getValue();
            snf = new NetSniffer(devName, PROMICIOUS_MODE,
                                 TIMEOUT_MS, cacheSize);
            if (ipAddr != "") {
                std::cout << "Your IP address: " << ipAddr << std::endl;
            }
            snf->setFilter(filterText);
            snf->setLoop(NUMBER_OF_PACKAGES);
        } else {
            std::vector<std::string> filenames = filenamesArg.getValue();
            snf = new NetSniffer(filenames[0].c_str(), cacheSize);
            snf->setFilter(filterText);
            snf->captureAll();
        }

        std::cout << "Hit rate: " << snf->getHitRate() << std::endl;
        delete snf;

/*
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
*/
    } catch (PcapException &e) {
        std::cout << e.what();
    } catch (TCLAP::ArgException &e) {
        std::cout << "Error: " << e.error() << " for arg " << e.argId();
    }

    return 0;
}
