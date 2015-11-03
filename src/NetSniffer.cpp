#include <arpa/inet.h>
#include <bitset>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include "NetSniffer.hpp"
#include "Md5HashedPayload.hpp"
#include "TcpIpInternetHeaders.hpp"


void parsePacket(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);


std::string NetSniffer::getIpAddress(void) const {
    for (pcap_addr_t *addresses = devInt->addresses; addresses != NULL;
        addresses = addresses->next) {

        if (addresses->addr->sa_family == AF_INET) {
            return std::string(inet_ntoa(((struct sockaddr_in*)addresses->addr)->sin_addr));
        }
    }
//  std::string str = "No AF_INET interfaces have been found";
}


NetSniffer::NetSniffer(std::string const &inputDevName,
                       bool promisModeOn,
                       int timeoutInMs,
                       int cacheSize):
    devInt(NULL),
    mask(0), net(0),
    compiledFilter(),
    packetCache_(cacheSize),
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
        handleErrors("Couldn't open device");
    }

    if (pcap_lookupnet(devName.c_str(), &net, &mask, errBuf) == -1) {
        handleErrors("Can't get netmask for device");
        net = 0;
        mask = 0;
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


NetSniffer::NetSniffer(const char *inputSavefile, int cacheSize):
    devInt(NULL),
    mask(0), net(0),
    compiledFilter(),
    packetCache_(cacheSize),
    onlineCapturing_(false)
{
    handle = pcap_open_offline(inputSavefile, errBuf);
    if (handle == NULL) {
        handleErrors("Couldn't open input savefile");
    }
}


void NetSniffer::setFilter(std::string const &filterText) {
    const char *filterExp = filterText.c_str();
    if (pcap_compile(handle, &compiledFilter, filterExp, 0, net) == -1) {
        std::string ErrorMsg = "Couldn't parse filter " + filterText;
        ErrorMsg += ": " + std::string(pcap_geterr(handle));
        handleErrors(ErrorMsg);
    }

    if (pcap_setfilter(handle, &compiledFilter) == -1) {
        std::string ErrorMsg = "Couldn't set filter " + filterText;
        ErrorMsg += ": " + std::string(pcap_geterr(handle));
        handleErrors(ErrorMsg);
    }   
}


void NetSniffer::setLoop(int numPkgs) const {
    u_char *params = (u_char*)(&packetCache_);
    if (pcap_loop(handle, numPkgs, parsePacket, params) == -1) {
        handleErrors("An error have occured during looping");
    }
}


void NetSniffer::captureAll() const {
    const u_char *packet = NULL;
    struct pcap_pkthdr header;
    u_char *params = (u_char*)(&packetCache_);

    while (packet = pcap_next(handle, &header)) {
        parsePacket(params, &header, packet);
    }
}

void NetSniffer::clearCache() {
    packetCache_.clear();
}


NetSniffer::~NetSniffer() {
    pcap_freecode(&compiledFilter);
    pcap_close(handle);
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

    ipHeader = (struct sniffIpHeader*)(packet + ETHER_HEADER_SIZE);
    ipSize = IP_HL(ipHeader) * 4;

    //TODO: вызывающий не может узнать о том, что что-то идет не так
    if (ipSize < 20) {
        std::cout << "Invalid IP header length: " << ipSize
                << " bytes" << std::endl;
        return;
    }

    tcpHeader = (struct sniffTcpHeader*)(packet + ETHER_HEADER_SIZE + ipSize);
    tcpSize = TCP_OFF(tcpHeader) * 4;
    if (tcpSize < 20) {
        std::cout << "Invalid TCP header length: " << tcpSize
                  << " bytes" << std::endl;
        return;
    }

    payload = (unsigned char *)(packet + ETHER_HEADER_SIZE + ipSize + tcpSize);
    int payloadSize = (int)(ntohs(ipHeader->ipTotLen)) - (int)(ipSize) - (int)(tcpSize);
    if (payloadSize < 0) {
        std::cout << "Invalid payload length: " << payloadSize 
                  << " bytes" << std::endl;
        return;
    }

    if (payloadSize == 0) {
        std::cout << "No payload present" << std::endl;
        return;
    }

    // std::cout << "Packet captured, payload length = " << payloadSize
    //           << " bytes" << std::endl;

    Md5HashedPayload HashedPayload(payload, payloadSize, true);

    void *vPtr = (void*)args;
    Cache *cache = (Cache*)vPtr;
    cache->add(HashedPayload);

    return;
}