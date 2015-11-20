#include <iostream>
#include <string>
#include <vector>
#include <tclap/CmdLine.h>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


const int NUMBER_OF_PACKAGES  = 768;
const bool PROMICIOUS_MODE  = false;
const int TIMEOUT_MS  = 100;


int main(int argc, char **argv) {
    try {

        TCLAP::CmdLine cmd("Description message", ' ', "0.9");

        TCLAP::ValueArg<std::int64_t> cacheSizeArg("", "cache_size",
                                          "Sets size of cache (in packets)",
                                          false, 256, "cache size, in KB");

        TCLAP::ValueArg<std::string> ipAddrArg(
                        "", "ip_addr", "Sets ip address of destination", false,
                        "", "ip address of destination"
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
        std::int64_t cacheSize = cacheSizeArg.getValue() * 1024;

        std::string ipAddr = ipAddrArg.getValue();
        std::string ipFilter = "";
        if (ipAddr != "") {
            ipFilter = "dst host " + ipAddr + " and ";
        }
        std::string filterText = "tcp port 80 and " + ipFilter;
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        NetSniffer *snf = NULL;
        Cache *cache = new Cache(cacheSize);

        if (isOnline) {
            std::string devName = devArg.getValue();
            snf = new NetSniffer(devName, PROMICIOUS_MODE,
                                 TIMEOUT_MS, cache);
            snf->setFilter(filterText);
            snf->setLoop(NUMBER_OF_PACKAGES);
            delete snf;
        } else {
            std::vector<std::string> filenames = filenamesArg.getValue();
            // for (auto filename in filenames) {} (?)
            for (std::size_t i = 0; i < filenames.size(); ++i) {
                snf = new NetSniffer(filenames[i].c_str(), cache);
                snf->setFilter(filterText);
                snf->captureAll();
                delete snf;
            }
        }

        std::cout << "Hit rate: " << cache->getHitRate() << std::endl;
        delete cache;
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
