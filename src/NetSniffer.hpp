#ifndef NETSNIFFER_HPP
#define NETSNIFFER_HPP


#include <pcap.h>
#include <exception>
#include <string>
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

    bool onlineCapturing_;
    struct bpf_program *compiledFilter;

    char errBuf[PCAP_ERRBUF_SIZE];
    Cache packetCache_;

    void handleErrors(const std::string &descrMsg) const {
        throw PcapException(descrMsg);
    }
public:
    NetSniffer(std::string const &inputDevName, bool promisModeOn,
        int timeoutInMs, int cacheSize);
    NetSniffer(const char *inputSavefile, int cacheSize);

    std::string getIpAddress(void) const;
    void setFilter(std::string const &filterText);
    void setLoop(int numPkgs = 1) const;
    void captureAll() const;
    void clearCache();
    ~NetSniffer();

    float getHitRate() const {
        return packetCache_.getHitRate();
    }
};


#endif
