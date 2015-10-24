#ifndef NETSNIFFER_HPP
#define NETSNIFFER_HPP

#include <pcap.h>
#include <exception>

class NetSniffer {
private:
    pcap_t *handle;
    pcap_if_t *devInt;
    const char *devName;

    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct bpf_program compiledFilter;

    char errBuf[PCAP_ERRBUF_SIZE];

    void handleErrors(std::string &descrMsg) const;

public:
    NetSniffer(std::string const &inputDevName, bool promisModeOn = false,
        int timeoutInMs = 100);

    std::string getIpAddress(void) const;
    void setFilter(std::string const &filterText);
    void setLoop(pcap_handler callbackFunc, int numPkgs = 1) const;
    ~NetSniffer();
};


class PcapException: std::exception {
private:
    std::string errMsgFromPcap;

public:
    PcapException(const std::string &errMsg);
    virtual const char * what() const throw();
    ~PcapException() throw();   
};


#endif
