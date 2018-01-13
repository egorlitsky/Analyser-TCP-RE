#include <cstdio>
#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <tclap/CmdLine.h>
#include "NetSniffer.hpp"
#include "StreamCacheStructure.hpp"
#include "CacheStructure.hpp"

#define STREAM_SIZE_MB 50

const bool PROMICIOUS_MODE  = false;
const int  TIMEOUT_MS       = 100;

bool withVlan   = false;
bool streamMode = false;
bool debugMode  = false;

std::size_t streamSize;
std::string searchType;

int         threadsAmount;      // enables multi-thread substring search, if specified
int         chunkSize;          // enables chunk-based caching, if specified
int         fileStreamsAmount;  // enables File streams

int main(int argc, char **argv) {

    try {

        TCLAP::CmdLine cmd("Description message", ' ', "1.3");

        TCLAP::ValueArg<std::size_t> cacheSizeArg("", "cache_size",
                            "Sets size of cache",
                            false, 8, "cache size, in MB");

        TCLAP::ValueArg<std::string> ipAddrArg(
                            "", "ip_addr", "Sets ip address of destination", false,
                            "", "ip address of destination");

        TCLAP::ValueArg<std::string> devArg("d", "device",
                            "Sets device to capture from",
                            true, "wlan0", "device name");
        
        TCLAP::MultiArg<std::string> filenamesArg(
                            "f", "filename", "Gets pcap filenames", true, "filenames");

        TCLAP::ValueArg<std::string> outputArg("o", "output_file",
                            "Sets file to write info",
                            false, "", "output filename");

        TCLAP::SwitchArg vlanArg("", "vlan",
                            "Indicates that packets contain vlan header",
                            cmd, false);

        std::string descr = "Sets number of packets to capture from online int";
        TCLAP::ValueArg<int> packetNumArg("n", "packet_number", descr.c_str(),
                            false, 768, "# of packets to capture");

        TCLAP::SwitchArg streamArg("", "streams",
                            "Separates all packets into streams and computes hit-rate for Flow-based"
                            " approach.", cmd, false);

        TCLAP::SwitchArg debugArg("", "debug",
                            "Enables Debug mode and writes data to text-file for each stream (TCP-flow)",
                            cmd, false);
        
        TCLAP::ValueArg<std::size_t> streamSizeArg("", "stream_size",
                            "Sets size of one stream",
                            false, STREAM_SIZE_MB, "stream size, in MB");
        
        TCLAP::ValueArg<std::string> searchTypeArg("s", "search_type",
                            "Sets the method of payload-search: find, custom_str_str (default), "
                            "boyer_moore, knuth_morris_pratt", false, "", "preferred search-method");

        TCLAP::ValueArg<int> threadsAmountArg("t", "threads_amount",
                            "Count of threads required for payload-search. One by default.",
                            false, 1, "# of threads for payload-search");

        TCLAP::ValueArg<int> chunkSizeArg("c", "chunk_size",
                            "Size of chunk. Enables chunk-based caching algorithm.",
                            false, 0, "chunk size for chunk-based algorithm");

        TCLAP::ValueArg<int> fileStreamsAmountArg("a", "file_streams_amount",
                            "Total amount of File TCP streams (stream data will be stored in file).",
                            false, 0, "amount of File streams");
        
        cmd.add(cacheSizeArg);
        cmd.add(streamSizeArg);
        cmd.add(ipAddrArg);
        cmd.xorAdd(devArg, filenamesArg);
        cmd.add(outputArg);
        cmd.add(searchTypeArg);
        cmd.add(packetNumArg);
        cmd.add(threadsAmountArg);
        cmd.add(chunkSizeArg);
        cmd.add(fileStreamsAmountArg);
        cmd.parse(argc, argv);


        bool isOnline = devArg.isSet();
        std::size_t cacheSize = cacheSizeArg.getValue() * 1024 * 1024;
        
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

        std::streambuf *buf;
        std::ofstream ofs;
        std::string output = outputArg.getValue();
        if (output != "") {
            ofs.open(output.c_str());
            buf = ofs.rdbuf();
        } else {
            buf = std::cout.rdbuf();
        }

        searchType = searchTypeArg.getValue();
        if (searchType == "") {
            searchType = SEARCH_CUSTOM_STR_STR;
        }

        if (searchType != SEARCH_FIND && searchType != SEARCH_CUSTOM_STR_STR &&
                searchType != SEARCH_BOYER_MOORE && searchType != SEARCH_KMP) {
            throw std::runtime_error("Search method is incorrect!");
        }

        threadsAmount     = threadsAmountArg.getValue();
        chunkSize         = chunkSizeArg.getValue();
        fileStreamsAmount = fileStreamsAmountArg.getValue();
        
        if (threadsAmount > 1 && chunkSize != 0) {
            throw std::runtime_error("Multi-thread mode is not compatible with chunk-based algorithm");
        }
        
        std::ostream out(buf);
        ICache* ic;
        
        streamMode = streamArg.getValue();
        debugMode  = debugArg.getValue();
        if (streamMode) {
            ic = new StreamCache(cacheSize);
        } else {
            ic = new Cache(cacheSize);
        }

        streamSize = streamSizeArg.getValue() * 1024 * 1024;

        if (isOnline) {
            int numberOfPackets = packetNumArg.getValue();;
            Reporter rep(numberOfPackets);
            out << "Online capturing" << std::endl;
            out << "Cache size: " << cacheSize / (1024 * 1024) << " MB" << std::endl;

            std::string devName = devArg.getValue();
            NetSniffer snf(devName, PROMICIOUS_MODE, TIMEOUT_MS, ic);
            snf.setFilter(filterText);
            snf.setLoop(&rep, numberOfPackets);
            out << "Hit rate: " << ic->getHitRate() << std::endl;
            out << "Collisions number: " << ic->getCollisionsNumber()
                << std::endl;
        } else {
            out << "Capturing from files" << std::endl;
            out << "Cache size: " << cacheSize / (1024  * 1024) << " MB" << std::endl;

            std::vector<std::string> filenames = filenamesArg.getValue();
            time_t timer1, timer2;
            std::uint64_t total_packet_count = 0;
            for (std::size_t i = 0; i < filenames.size(); ++i) {
                NetSniffer snf(filenames[i].c_str(), ic);
                snf.setFilter(filterText);
                Reporter rep(0);

                time(&timer1);
                std::uint64_t packet_count = snf.captureAll(&rep);
                time(&timer2);

                out << std::endl;
                out << i + 1 << ". After " << filenames[i]
                    << " capturing" << std::endl;
                out << "   Number of captured packets: " << packet_count
                    << std::endl;
                out << "   Hit rate after: " << ic->getHitRate() << std::endl;
                out << "   Collisions number after: "
                    << ic->getCollisionsNumber() << std::endl;
                out << "   Accuired time, secs : "
                    << difftime(timer2, timer1) << std::endl;
                std::cout << std::endl;

                total_packet_count += packet_count;
            }
            out << "Total number of captured packets: " << total_packet_count
                << std::endl;
            out << "Total hit rate: " << ic->getHitRate() << std::endl;
            out << "Total collisions' number: "
                << ic->getCollisionsNumber() << std::endl;
        }
    } catch (PcapException &e) {
        std::cout << e.what();
    } catch (TCLAP::ArgException &e) {
        std::cout << "Error: " << e.error() << " for arg " << e.argId();
    }

    return 0;
}
