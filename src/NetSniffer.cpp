#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include "NetSniffer.hpp"
#include "TcpIpInternetHeaders.hpp"


extern bool withVlan;
extern bool withStreams;


struct Params {
    Reporter *rep;
    Cache *cache;
    Params(Reporter *r, Cache *c): rep(r), cache(c) {}
};


void parsePacket(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);


std::string NetSniffer::getIpAddress(void) const {
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


NetSniffer::NetSniffer(std::string const &inputDevName,
                       bool promisModeOn,
                       int timeoutInMs,
                       Cache *cache):
    devInt(NULL),
    compiledFilter(NULL),
    packetCache_(cache),
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


NetSniffer::NetSniffer(const char *inputSavefile, Cache *cache):
    devInt(NULL),
    compiledFilter(NULL),
    packetCache_(cache),
    onlineCapturing_(false)
{
    handle = pcap_open_offline(inputSavefile, errBuf);
    if (handle == NULL) {
        handleErrors("Couldn't open input savefile");
    }
}


void NetSniffer::setFilter(std::string const &filterText) {
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


void NetSniffer::setLoop(Reporter *rep, int numPkgs) const {
    if (packetCache_ == NULL) {
        handleErrors("No cache to store info!");
    }
    Params p(rep, packetCache_);
    u_char *params = (u_char*)(&p);

    if (pcap_loop(handle, numPkgs, parsePacket, params) == -1) {
        handleErrors("An error have occured during looping");
    }
    
    if (rep != NULL) {
        rep->fin();
    }
}


std::uint64_t NetSniffer::captureAll(Reporter *rep) const {
    const u_char *packet = NULL;
    struct pcap_pkthdr header;

    if (packetCache_ == NULL) {
        handleErrors("No cache to store info!");
    }
    Params p(rep, packetCache_);
    u_char *params = (u_char*)(&p);

    std::uint64_t cnt = 0;
    while (packet = pcap_next(handle, &header)) {
        parsePacket(params, &header, packet);
        cnt += 1;
    }
    
    if (withStreams) {
        for(auto stream : p.cache->tcpStreams) {
            const char *aux = inet_ntoa(stream.ipSrc);
            const char *ipSrc = strcpy(new char[strlen(aux)+1], aux);

            aux = inet_ntoa(stream.ipDst);
            const char *ipDst = strcpy(new char[strlen(aux)+1], aux);
            
            std::ostringstream oss;
            oss << "" << ipSrc << "_" << ipDst << "_" << 
                    stream.tcpSport << "_" << stream.tcpDport << ".txt";
            
            std::string file_name = oss.str();   
            std::ofstream fout(file_name, std::ios::binary);

            for(auto packet : stream.getPackets()) {
                for (int i = 0; i < packet.second.size(); ++i) {
                    fout << packet.second[i];
                }
            }
            
            fout.close();
        }
    }
        
    if (rep != NULL) {
        rep->fin();
    }

    return cnt;
}


void NetSniffer::setCache(Cache *cache) {
    packetCache_ = cache;
}


Cache *NetSniffer::getCache(void) {
    return packetCache_;
}


NetSniffer::~NetSniffer() {
    if (compiledFilter != NULL) {
        pcap_freecode(compiledFilter);
        delete compiledFilter;
    }
    if (handle != NULL) {
        pcap_close(handle);
    }
}


PcapException::PcapException(const std::string &errMsg): 
        exception(), errMsgFromPcap(errMsg) {}


const char *PcapException::what() const throw() {
    return errMsgFromPcap.c_str();
}


PcapException::~PcapException() throw() {}


void parsePacket(u_char *args, const struct pcap_pkthdr *header, 
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
   
    Md5HashedPayload HashedPayload(payload, payloadSize, true);
    p->cache->add(HashedPayload);
        
    if (withStreams) {
        u_int tcpSeq = (u_int)htonl(tcpHeader->tcpSeq);
    
        struct in_addr ipSrc = ipHeader->ipSrc;
        struct in_addr ipDst = ipHeader->ipDst;

        u_short tcpSport = ntohs(tcpHeader->tcpSport);
        u_short tcpDport = ntohs(tcpHeader->tcpDport);

        p->cache->addPacket(ipSrc, ipDst, tcpSport, tcpDport,
                tcpSeq, payload, payloadSize);
    }
    return;
}
