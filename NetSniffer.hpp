#ifndef NETSNIFFER_HPP
#define NETSNIFFER_HPP


#include <pcap.h>
#include <exception>
#include "CacheStructure.hpp"


class PcapException: std::exception {
private:
    std::string errMsgFromPcap;

public:
    PcapException(const std::string &errMsg);
    virtual const char * what() const throw();
    ~PcapException() throw();   
};


class NetSniffer {
private:
    pcap_t *handle;
    pcap_if_t *devInt;
    const char *devName;

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program compiledFilter;

    char errBuf[PCAP_ERRBUF_SIZE];
    Cache packetCache_;

    void handleErrors(const std::string &descrMsg) const {
        throw PcapException(descrMsg);
    }
public:
    NetSniffer(std::string const &inputDevName, bool promisModeOn,
        int timeoutInMs, int cacheSize);

    std::string getIpAddress(void) const;
    void setFilter(std::string const &filterText);
    void setLoop(int numPkgs = 1) const;
    ~NetSniffer();
};


#endif
