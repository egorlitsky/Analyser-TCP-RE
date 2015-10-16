#include <stdio.h>
#include <iostream>
#include <arpa/inet.h>
#include "NetSniffer.hpp"


void NetSniffer::handleErrors(std::string &descrMsg) const {
	//std::cout << descrMsg << std::endl;
	throw PcapException(descrMsg);
}


std::string NetSniffer::getIpAddress(void) const {
	for (pcap_addr_t *addresses = devInt->addresses; addresses != NULL;
		addresses = addresses->next) {

		if (addresses->addr->sa_family == AF_INET) {
			return std::string(inet_ntoa(((struct sockaddr_in*)addresses->addr)->sin_addr));
		}
	}
	
//	std::string str = "No AF_INET interfaces have been found";
// 	return str + std::string(std::endl);
}


NetSniffer::NetSniffer(std::string const &inputDevName, bool promisModeOn,
	int timeoutInMs): devInt(NULL), mask(0), net(0), compiledFilter()
{
	if (inputDevName.empty()) {
		devName = pcap_lookupdev(errBuf);
		if (devName == NULL) {
			std::string ErrorMsg = "Couldn't find default device";
			handleErrors(ErrorMsg);
		}

	} else {
		devName = inputDevName.c_str();
	}

	handle = pcap_open_live(devName, BUFSIZ, promisModeOn, timeoutInMs, errBuf);
	if (handle == NULL) {
		std::string ErrorMsg = "Couldn't open device";
		handleErrors(ErrorMsg);
	}

	if (pcap_lookupnet(devName, &net, &mask, errBuf) == -1) {
		std::string ErrorMsg = "Can't get netmask for device";
		handleErrors(ErrorMsg);
		net = 0;
		mask = 0;
	}


	pcap_if_t *allDevs;
	if(pcap_findalldevs(&allDevs, errBuf)) {
		std::string ErrorMsg = "Couldn't get list of interfaces";
		handleErrors(ErrorMsg);
	}

	pcap_if_t *device = allDevs;
	for (pcap_if_t *device = allDevs; device != NULL; device = device->next) {
		if (!std::string(device->name).compare(std::string(devName)))
			devInt = device;
	}
}


void NetSniffer::setFilter(std::string const &filterText) {
	const char *filterExp = filterText.c_str();

	if (pcap_compile(handle, &compiledFilter, filterExp, 0, net) == -1) {
		std::string ErrorMsg = "Couldn't parse filter " + filterText;
		ErrorMsg += ": " + std::string(pcap_geterr(handle));
		// handleErrors(ErrorMsg, std::string(pcap_geterr(handle)));
		handleErrors(ErrorMsg);
	}

	if (pcap_setfilter(handle, &compiledFilter) == -1) {
		std::string ErrorMsg = "Couldn't set filter " + filterText;
		ErrorMsg += ": " + std::string(pcap_geterr(handle));
		// handleErrors(ErrorMsg, std::string(pcap_geterr(handle)));
		handleErrors(ErrorMsg);
	}	
}


void NetSniffer::setLoop(pcap_handler callbackFunc, int numPkgs) const {
	if (pcap_loop(handle, numPkgs, callbackFunc, NULL) == -1) {
		std::string ErrorMsg = "An error have occured during looping";
		handleErrors(ErrorMsg);
	}
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
