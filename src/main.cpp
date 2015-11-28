#include <cstdio>
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

        TCLAP::ValueArg<std::size_t> cacheSizeArg("", "cache_size",
                                          "Sets size of cache",
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

        TCLAP::ValueArg<std::string> outputArg("o", "output_file",
                                               "Sets file to write info",
                                               false, "", "output filename");

        cmd.add(cacheSizeArg);
        cmd.add(ipAddrArg);
        cmd.xorAdd(devArg, filenamesArg);
        cmd.add(outputArg);
        cmd.parse(argc, argv);


        bool isOnline = devArg.isSet();
        std::size_t cacheSize = cacheSizeArg.getValue() * 1024;

        std::string ipAddr = ipAddrArg.getValue();
        std::string ipFilter = "";
        if (ipAddr != "") {
            ipFilter = "dst host " + ipAddr + " and ";
        }
        std::string filterText = "tcp and " + ipFilter;
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        NetSniffer *snf = NULL;
        Cache cache(cacheSize);

        std::string output = outputArg.getValue();
        if (output != "") {
            freopen(output.c_str(), "w", stdout);
        }

        if (isOnline) {
            std::string devName = devArg.getValue();
            snf = new NetSniffer(devName, PROMICIOUS_MODE,
                                 TIMEOUT_MS, &cache);
            snf->setFilter(filterText);
            snf->setLoop(NUMBER_OF_PACKAGES);
            delete snf;
        } else {
            std::vector<std::string> filenames = filenamesArg.getValue();
            // for (auto filename in filenames) {} (?)
            for (std::size_t i = 0; i < filenames.size(); ++i) {
                snf = new NetSniffer(filenames[i].c_str(), &cache);
                snf->setFilter(filterText);
                snf->captureAll();
                delete snf;
            }
        }

        std::cout << "Hit rate: " << cache.getHitRate() << std::endl;

    } catch (PcapException &e) {
        std::cout << e.what();
    } catch (TCLAP::ArgException &e) {
        std::cout << "Error: " << e.error() << " for arg " << e.argId();
    }

    return 0;
}
