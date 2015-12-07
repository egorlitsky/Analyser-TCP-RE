#include <cstdio>
#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <tclap/CmdLine.h>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"


const bool PROMICIOUS_MODE  = false;
const int TIMEOUT_MS  = 100;


long long capturedPacketNumber = 0;
bool withVlan = false;


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

        TCLAP::SwitchArg vlanArg("", "vlan",
                                 "Indicates that packets contain vlan header",
                                 cmd, false);

        std::string descr = "Sets number of packets to capture from online int";
        TCLAP::ValueArg<int> packetNumArg("n", "packet_number", descr.c_str(),
                                          false, 768, "# of packets to capture");

        cmd.add(cacheSizeArg);
        cmd.add(ipAddrArg);
        cmd.xorAdd(devArg, filenamesArg);
        cmd.add(outputArg);
        cmd.add(packetNumArg);
        cmd.parse(argc, argv);


        bool isOnline = devArg.isSet();
        std::size_t cacheSize = cacheSizeArg.getValue() * 1024;

        std::string ipAddr = ipAddrArg.getValue();
        std::string ipFilter = "";
        if (ipAddr != "") {
            ipFilter = "dst host " + ipAddr + " and ";
        }
        std::string filterText = "tcp and " + ipFilter;
        filterText += "(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2))";
        filterText += " != 0)";

        withVlan = vlanArg.getValue();
        if (withVlan) {
            filterText = "vlan and " + filterText;
        }

        NetSniffer *snf = NULL;
        Cache cache(cacheSize);

        std::streambuf *buf;
        std::ofstream ofs;
        std::string output = outputArg.getValue();
        if (output != "") {
            // freopen(output.c_str(), "w", stdout);
            ofs.open(output.c_str());
            buf = ofs.rdbuf();
        } else {
            buf = std::cout.rdbuf();
        }
        std::ostream out(buf);


        if (isOnline) {
            int numberOfPackets = packetNumArg.getValue();
            out << "Online capturing" << std::endl;
            out << "Cache size: " << cacheSize / 1024 << "KB" << std::endl;

            std::string devName = devArg.getValue();
            snf = new NetSniffer(devName, PROMICIOUS_MODE,
                                 TIMEOUT_MS, &cache);
            snf->setFilter(filterText);
            snf->setLoop(numberOfPackets);
            delete snf;
            out << "Hit rate: " << cache.getHitRate() << std::endl;
        } else {
            out << "Capturing from files" << std::endl;
            out << "Cache size: " << cacheSize / 1024 << " KB" << std::endl;

            std::vector<std::string> filenames = filenamesArg.getValue();
            time_t timer1, timer2;
            std::uint64_t packet_count = 0;
            for (std::size_t i = 0; i < filenames.size(); ++i) {
                snf = new NetSniffer(filenames[i].c_str(), &cache);
                snf->setFilter(filterText);

                time(&timer1);
                packet_count += snf->captureAll();
                time(&timer2);

                delete snf;

                std::cout << "\rFile analysis completed    " << std::endl;
                out << std::endl;
                out << i + 1 << ". After " << filenames[i]
                    << " capturing" << std::endl;
                out << "   Number of captured packets: " << packet_count
                    << std::endl;
                out << "   Hit rate: " << cache.getHitRate() << std::endl;
                out << "   Accuired time, secs : "
                    << difftime(timer2, timer1) << std::endl;

                capturedPacketNumber = 0;
                std::cout << std::endl;
            }
        }

    } catch (PcapException &e) {
        std::cout << e.what();
    } catch (TCLAP::ArgException &e) {
        std::cout << "Error: " << e.error() << " for arg " << e.argId();
    }

    return 0;
}
