#include <iostream>
#include <bitset>
#include "NetSniffer.hpp"
#include "TcpIpInternetHeaders.hpp"
#include "Md5HashedPayload.hpp"

//TODO: всю работу с libpcap я бы перенес в NetSniffer


void parsePacket(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet)
{
    const struct sniffEtherHeader *ethernetHeader;
    const struct sniffIpHeader *ipHeader;
    const struct sniffTcpHeader *tcpHeader;
    // u_char *payload;
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
        std::cout << "Invalid TCP header length: " << tcpSize << " bytes" << std::endl;
        return;
    }

    // payload = (u_char *)(packet + ETHER_HEADER_SIZE + ipSize + tcpSize);
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

    std::cout << "Packet captured, payload length = " << payloadSize
              << " bytes" << std::endl;

    Md5HashedPayload HashedPayload(payload, payloadSize);

    return;
}


int main() {
    std::string devName = "wlan0";
    int numPkgs = 30;

    try {
        NetSniffer snf(devName);
        std::cout << snf.getIpAddress() << std::endl;

        std::string filterText = "tcp port 80 and dst host " + snf.getIpAddress();
        filterText += " and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";

        snf.setFilter(filterText);
        snf.setLoop(parsePacket, numPkgs);
    } catch (PcapException &e) {
        std::cout << e.what();
    }

    return 0;
}
