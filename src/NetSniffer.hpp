#ifndef NETSNIFFER_HPP
#define NETSNIFFER_HPP


#include <cstdint>
#include <exception>
#include <string>
#include <pcap.h>
#include "ICache.hpp"
#include "Reporter.hpp"


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

    bool onlineCapturing_;
    struct bpf_program *compiledFilter;

    char errBuf[PCAP_ERRBUF_SIZE];
    ICache *packetCache_;

    void handleErrors(const std::string &descrMsg) const {
        throw PcapException(descrMsg);
    }
public:
    NetSniffer(std::string const &inputDevName, bool promisModeOn,
        int timeoutInMs, ICache *cache);
    NetSniffer(const char *inputSavefile, ICache *cache);

    std::string getIpAddress(void) const;
    void setFilter(std::string const &filterText);
    void setLoop(Reporter *rep, int numPkgs) const;
    std::uint64_t captureAll(Reporter *rep) const;
    ~NetSniffer();
    void setCache(ICache *c_);
    ICache *getCache(void);
};


#endif
