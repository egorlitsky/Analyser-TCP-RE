#ifndef TCPIPINTERNETHEADERS_HPP
#define TCPIPINTERNETHEADERS_HPP

#include <arpa/inet.h>


#define ETHER_HEADER_SIZE 14
#define ETHER_ADDR_LEN 6


struct sniffEtherHeader {
		u_char		etherDhost[ETHER_ADDR_LEN];
		u_char		etherShost[ETHER_ADDR_LEN];
		u_short		EtherPtype;
};


struct sniffIpHeader {
		u_char		ipVerHlen;	/* NB: header length in 32-bit words */
		u_char		ipTos;
		u_short 	ipTotLen;	/* NB: total length in octets */
		u_short 	ipId;
		u_short 	ipOffset;			
#define	IP_RF		0x8000		/* reserved fragment flag */
#define	IP_DF		0x4000		/* dont fragment flag */
#define	IP_MF		0x2000		/* more fragments flag */
#define	IP_OFFMASK	0x1fff		/* mask for fragmenting bits */	
		u_char		ipTtl;
		u_char		ipProt;
		u_short		ipSum;
		struct in_addr ipSrc, ipDst;
};

#define	IP_V(ip)	(((ip)->ipVerHlen) >> 4)
#define	IP_HL(ip)	(((ip)->ipVerHlen) & 0x0f)


struct sniffTcpHeader {
		u_short		tcpSport;
		u_short		tcpDport;
		u_int		tcpSeq;
		u_int		tcpAck;
		u_char		tcpOffRsvd;
		u_char		tcpFlags;
#define	TCP_FIN		0x01
#define	TCP_SYN		0x02
#define	TCP_RST		0x04
#define	TCP_PUSH	0x08
#define	TCP_ACK		0x10
#define	TCP_URG		0x20
#define	TCP_ECE		0x40
#define	TCP_CWR		0x80
#define	TCP_FLAGS	(TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
		u_short		tcpWin;
		u_short		tcpSum;
		u_short		tcpUrp;
};


/* number of 32-bit words in TCP header */
#define	TCP_OFF(th)	(((th)->tcpOffRsvd & 0xf0) >> 4)


#endif
