#ifndef STREAM_NETSNIFFER_HPP
#define STREAM_NETSNIFFER_HPP

#include <cstdint>
#include <exception>
#include <string>
#include <set>
#include <pcap.h>
#include "StreamCacheStructure.hpp"
#include "Reporter.hpp"
#include "TcpStream.hpp"


class StreamPcapException: std::exception {
private:
    std::string errMsgFromPcap;

public:
    StreamPcapException(const std::string &errMsg);
    virtual const char * what() const throw();
    ~StreamPcapException() throw();
};

class StreamNetSniffer {
private:
    pcap_t *handle;
    pcap_if_t *devInt;

    bool onlineCapturing_;
    struct bpf_program *compiledFilter;

    char errBuf[PCAP_ERRBUF_SIZE];
    StreamCache *streamCache_;

    void handleErrors(const std::string &descrMsg) const {
        throw StreamPcapException(descrMsg);
    }
public:
    StreamNetSniffer(std::string const &inputDevName, bool promisModeOn,
        int timeoutInMs, StreamCache *cache);
    StreamNetSniffer(const char *inputSavefile, StreamCache *cache);

    std::string getIpAddress(void) const;
    void setFilter(std::string const &filterText);
    void setLoop(Reporter *rep, int numPkgs) const;
    std::uint64_t captureAll(Reporter *rep) const;
    ~StreamNetSniffer();
    void setCache(StreamCache *c_);
    StreamCache *getCache(void);
};


#endif
