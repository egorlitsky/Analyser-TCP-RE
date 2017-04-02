#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include "StreamNetSniffer.hpp"
#include "TcpIpInternetHeaders.hpp"

extern bool withVlan;

struct Params {
    Reporter *rep;
    StreamCache *cache;
    Params(Reporter *r, StreamCache *c): rep(r), cache(c) {}
};


void parseSegment(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);


std::string StreamNetSniffer::getIpAddress(void) const {
    if (devInt == NULL) {
        handleErrors("No device interface to capture");
    }

    for (pcap_addr_t *addresses = devInt->addresses; addresses != NULL;
        addresses = addresses->next) {

        if (addresses->addr->sa_family == AF_INET) {
            return std::string(inet_ntoa(((struct sockaddr_in*)addresses->addr)->sin_addr));
        }
    }

    handleErrors( "No AF_INET interfaces have been found");
}


StreamNetSniffer::StreamNetSniffer(std::string const &inputDevName,
                       bool promisModeOn,
                       int timeoutInMs,
                       StreamCache *cache):
    devInt(NULL),
    compiledFilter(NULL),
    streamCache_(cache),
    onlineCapturing_(true)
{
    std::string devName;
    if (inputDevName.empty()) {
        const char * defDevName = pcap_lookupdev(errBuf);
        if (defDevName == NULL) {
            handleErrors("Couldn't find default device");
        }
        devName = defDevName;

    } else {
        devName = inputDevName;
    }

    handle = pcap_open_live(devName.c_str(), BUFSIZ, promisModeOn,
                            timeoutInMs, errBuf);
    if (handle == NULL) {
        handleErrors("Couldn't open device named " + devName);
    }

    pcap_if_t *allDevs;
    if(pcap_findalldevs(&allDevs, errBuf)) {
        handleErrors("Couldn't get list of interfaces");
    }

    pcap_if_t *device = allDevs;
    for (pcap_if_t *device = allDevs; device != NULL; device = device->next) {
        if (!std::string(device->name).compare(devName))
            devInt = device;
    }
}


StreamNetSniffer::StreamNetSniffer(const char *inputSavefile, StreamCache *cache):
    devInt(NULL),
    compiledFilter(NULL),
    streamCache_(cache),
    onlineCapturing_(false)
{
    handle = pcap_open_offline(inputSavefile, errBuf);
    if (handle == NULL) {
        handleErrors("Couldn't open input savefile");
    }
}


void StreamNetSniffer::setFilter(std::string const &filterText) {
    if (handle == NULL) {
        handleErrors("No handle is set");
    }

    if (compiledFilter == NULL) {
        compiledFilter = new bpf_program();
    } else {
        pcap_freecode(compiledFilter);
        delete compiledFilter;
    }
    const char *filterExp = filterText.c_str();
    if (pcap_compile(handle, compiledFilter, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::string ErrorMsg = "Couldn't parse filter " + filterText;
        ErrorMsg += ": " + std::string(pcap_geterr(handle));
        handleErrors(ErrorMsg);
    }

    if (pcap_setfilter(handle, compiledFilter) == -1) {
        std::string ErrorMsg = "Couldn't set filter " + filterText;
        ErrorMsg += ": " + std::string(pcap_geterr(handle));
        handleErrors(ErrorMsg);
    }   
}


void StreamNetSniffer::setLoop(Reporter *rep, int numPkgs) const {
    if (streamCache_ == NULL) {
        handleErrors("No cache to store info!");
    }
    Params p(rep, streamCache_);
    u_char *params = (u_char*)(&p);

    if (pcap_loop(handle, numPkgs, parseSegment, params) == -1) {
        handleErrors("An error have occured during looping");
    }
    
    if (rep != NULL) {
        rep->fin();
    }
}


std::uint64_t StreamNetSniffer::captureAll(Reporter *rep) const {
    const u_char *packet = NULL;
    struct pcap_pkthdr header;

    if (streamCache_ == NULL) {
        handleErrors("No cache to store info!");
    }
    Params p(rep, streamCache_);
    u_char *params = (u_char*)(&p);

    std::uint64_t cnt = 0;
    while (packet = pcap_next(handle, &header)) {
        parseSegment(params, &header, packet);
        cnt += 1;
    }
    
    for(StreamCache::cacheIterType it = p.cache->_cache.begin(); it != p.cache->_cache.end(); ++it) {
        const char *aux = inet_ntoa(it->stream.ipSrc);
        const char *ipSrc = strcpy(new char[strlen(aux)+1], aux);

        aux = inet_ntoa(it->stream.ipDst);
        const char *ipDst = strcpy(new char[strlen(aux)+1], aux);

        std::ostringstream oss;
        oss << "" << ipSrc << "_" << ipDst << "_" << 
                it->stream.tcpSport << "_" << it->stream.tcpDport << ".txt";

        std::string file_name = oss.str();   
        std::ofstream fout(file_name, std::ios::binary);

        // output like the Wireshark output in 'Follow TCP Stream'
        for(auto packet : it->stream.packets) {
            for (int i = 0; i < packet.second.size(); ++i) {
                
                char c = packet.second[i],
                        wiresharkChar = c >= ' ' && c < 0x7f ? c : '.';
                
                if (c == '\n' || c == '\r' || c == '\t') {
                    fout << c;
                } else {
                    fout << wiresharkChar;
                }
            }
        }

        fout.close();
    }
        
    if (rep != NULL) {
        rep->fin();
    }

    return cnt;
}

void StreamNetSniffer::setCache(StreamCache *cache) {
    streamCache_ = cache;
}

StreamCache *StreamNetSniffer::getCache(void) {
    return streamCache_;
}


StreamNetSniffer::~StreamNetSniffer() {
    if (compiledFilter != NULL) {
        pcap_freecode(compiledFilter);
        delete compiledFilter;
    }
    if (handle != NULL) {
        pcap_close(handle);
    }
}


StreamPcapException::StreamPcapException(const std::string &errMsg): 
        exception(), errMsgFromPcap(errMsg) {}


const char *StreamPcapException::what() const throw() {
    return errMsgFromPcap.c_str();
}


StreamPcapException::~StreamPcapException() throw() {}


void parseSegment(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet)
{
    const struct sniffEtherHeader *ethernetHeader;
    const struct sniffIpHeader *ipHeader;
    const struct sniffTcpHeader *tcpHeader;
    unsigned char *payload;

    u_int ipSize;   /* in octets */
    u_int tcpSize;  /* in octets */

    ethernetHeader = (struct sniffEtherHeader*)(packet);

    int ethHeaderLen = ETHER_HEADER_SIZE + (4 * withVlan);
    ipHeader = (struct sniffIpHeader*)(packet + ethHeaderLen);
    ipSize = IP_HL(ipHeader) * 4;

    if (ipSize < 20) {
        return;
    }

    tcpHeader = (struct sniffTcpHeader*)(packet + ethHeaderLen + ipSize);
    tcpSize = TCP_OFF(tcpHeader) * 4;
    if (tcpSize < 20) {
        return;
    }

    payload = (unsigned char *)(packet + ethHeaderLen + ipSize + tcpSize);
    int payloadSize = (int)(ntohs(ipHeader->ipTotLen)) - (int)(ipSize) - (int)(tcpSize);
    if (payloadSize <= 0) {
        return;
    }

    void *vPtr = (void*)args;
    Params *p = (Params*)vPtr;

    if (p->rep != NULL) {
        p->rep->inc();
    }
   
    u_int tcpSeq = (u_int)htonl(tcpHeader->tcpSeq);

    struct in_addr ipSrc = ipHeader->ipSrc;
    struct in_addr ipDst = ipHeader->ipDst;

    u_short tcpSport = ntohs(tcpHeader->tcpSport);
    u_short tcpDport = ntohs(tcpHeader->tcpDport);

    p->cache->add(ipSrc, ipDst, tcpSport, tcpDport,
            tcpSeq, payload, payloadSize);
        
    return;
}