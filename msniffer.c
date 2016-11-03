#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "pcap/pcap.h"

static char *ip_addr(uint8_t *addr, char *buf, size_t sz)
{
	struct in_addr in;
	
	(void)memcpy(&in.s_addr, addr, sizeof(in.s_addr));
	(void)snprintf(buf, sz, "%s", inet_ntoa(in));

	return (buf);
}

static const struct eth_proto {
	int				ep_protoid; 	
	const char 		*ep_str;
} eth_proto_str[] = {
	{ETHERTYPE_PUP, "PUP"},
	{ETHERTYPE_SPRITE, "SPRITE"},
	{ETHERTYPE_IP, "IP"},
	{ETHERTYPE_ARP, "ARP"},
	{ETHERTYPE_REVARP, "REVARP"},
	{ETHERTYPE_AT, "AT"},
	{ETHERTYPE_AARP, "AARP"},
	{ETHERTYPE_VLAN, "VLAN"},
	{ETHERTYPE_IPX, "IPX"},
	{ETHERTYPE_IPV6, "IPV6"},
	{ETHERTYPE_LOOPBACK, "ETHERTYPE_LOOPBACK"},
	{ETHERTYPE_TRAIL, "TRAIL"},
	{ETHERTYPE_NTRAILER, "NTRAILER"},
};

static const char *eth_proto_string(int eth_type)
{
	int i;
	for (i = 0; i < sizeof(eth_proto_str)/sizeof(struct eth_proto); i++) {
		if (eth_type == eth_proto_str[i].ep_protoid) {
			return (eth_proto_str[i].ep_str);
		}
	}

	return (NULL);
}

static void tcp_print(const u_char *tcphdr)
{

}

static void udp_print(const u_char *udphdr)
{
}


static void print_icmp_echoreply(const struct icmphdr *icmphdr, const uint8_t *optdata, size_t optdatalen)
{
//Echo or Echo Reply Message
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |     Code      |          Checksum             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Identifier          |        Sequence Number        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Data ...
//   +-+-+-+-+-

	int icmpcode_echoreply = icmphdr->code; 

	if (icmpcode_echoreply != 0) {
		(void)fprintf(stderr, "icmp echo reply message code must be 0\n");
		return;
	}

printf("------------------------------------------------------> ping应答. code = %d\n", icmpcode_echoreply);
	printf("icmp code 0x%02x\n", icmpcode_echoreply);
	printf("Checksum 0x%04x\n", ntohs(icmphdr->checksum));
	printf("Identifier 0x%04x\n", ntohs(icmphdr->un.echo.id));
	printf("Sequence Number %hu\n", ntohs(icmphdr->un.echo.sequence));

	printf("Optdata:\n");
	size_t i;
	for (i = 0; i < optdatalen; i++) {
		printf("%02x ", optdata[i]);
		if ((i + 1) % 16 == 0)	printf("\n");
	}
	printf("\n");

#if 0
	switch (icmpcode) {
		case 0:	/* 回显应答 -- ping应答 */
			break;
	}
#endif
}

static const char *icmp_dest_unreach_reason_str[NR_ICMP_UNREACH + 1] = {
#if 0
/* 0  */[ICMP_NET_UNREACH] = "Network Unreachable",
/* 1  */[ICMP_HOST_UNREACH] = "Host Unreachable",
/* 2  */[ICMP_PROT_UNREACH] = "Protocol Unreachable",
/* 3  */[ICMP_PORT_UNREACH] = "Port Unreachable",
/* 4  */[ICMP_FRAG_NEEDED] = "Fragmentation Needed/DF set",
/* 5  */[ICMP_SR_FAILED] = "Source Route failed",
/* 6  */[ICMP_NET_UNKNOWN] = "Destination network unknown",
/* 7  */[ICMP_HOST_UNKNOWN] = "Destination host unknown",	
/* 8  */[ICMP_HOST_ISOLATED] = "Source host isolated",	
/* 9  */[ICMP_NET_ANO] = "Network administratively prohibited",
/* 10 */[ICMP_HOST_ANO] = "Host administratively prohibited",
/* 11 */[ICMP_NET_UNR_TOS] = "Network unreachable for ToS",
/* 12 */[ICMP_HOST_UNR_TOS] = "Host unreachable for ToS",
/* 13 */[ICMP_PKT_FILTERED] = "Packet filtered",
/* 14 */[ICMP_PREC_VIOLATION] = "Precedence violation",
/* 15 */[ICMP_PREC_CUTOFF] = "Precedence cut off",
#else
#define DEFINE_ICMP_UNREACH_REASON(N, S) [ICMP_##N] = S
	DEFINE_ICMP_UNREACH_REASON(NET_UNREACH, "Network Unreachable"),
	DEFINE_ICMP_UNREACH_REASON(HOST_UNREACH, "Host Unreachable"),
	DEFINE_ICMP_UNREACH_REASON(PROT_UNREACH, "Protocol Unreachable"),
	DEFINE_ICMP_UNREACH_REASON(PORT_UNREACH, "Port Unreachable"),
	DEFINE_ICMP_UNREACH_REASON(FRAG_NEEDED, "Fragmentation Needed/DF set"),
	DEFINE_ICMP_UNREACH_REASON(SR_FAILED, "Source Route failed"),
	DEFINE_ICMP_UNREACH_REASON(NET_UNKNOWN, "Destination network unknown"),
	DEFINE_ICMP_UNREACH_REASON(HOST_UNKNOWN, "Destination host unknown"),
	DEFINE_ICMP_UNREACH_REASON(HOST_ISOLATED, "Source host isolated"),
	DEFINE_ICMP_UNREACH_REASON(NET_ANO, "Network administratively prohibited"),
	DEFINE_ICMP_UNREACH_REASON(HOST_ANO, "Host administratively prohibited"),
	DEFINE_ICMP_UNREACH_REASON(NET_UNR_TOS, "Network unreachable for ToS"),
	DEFINE_ICMP_UNREACH_REASON(HOST_UNR_TOS, "Host unreachable for ToS"),
	DEFINE_ICMP_UNREACH_REASON(PKT_FILTERED, "Packet filtered"),
	DEFINE_ICMP_UNREACH_REASON(PREC_VIOLATION, "Precedence violation"),
	DEFINE_ICMP_UNREACH_REASON(PREC_CUTOFF, "Precedence cut off"),
#undef DEFINE_ICMP_UNREACH_REASON
#endif
};

static void print_icmp_dest_unreach(const struct icmphdr *icmphdr)
{
	int icmpcode_unreach = icmphdr->code; 
	if (icmpcode_unreach > NR_ICMP_UNREACH) {
		(void)fprintf(stderr, "Unknown icmp unreach code %d\n", icmpcode_unreach);
		return;
	}
	
	printf("Destination Unreachable: [%s]\n", icmp_dest_unreach_reason_str[icmpcode_unreach]);

	switch (icmpcode_unreach) {
		case ICMP_NET_UNREACH:		/* 0  -- Network Unreachable */
			break;
		case ICMP_HOST_UNREACH:		/* 1  -- Host Unreachable */
			break;
		case ICMP_PROT_UNREACH:		/* 2  -- Protocol Unreachable */
			break;
		case ICMP_PORT_UNREACH:		/* 3  -- Port Unreachable */
			break;
		case ICMP_FRAG_NEEDED:		/* 4  -- Fragmentation Needed/DF set */
			break;
		case ICMP_SR_FAILED:		/* 5  -- Source Route failed */
			break;
		case ICMP_NET_UNKNOWN:		/* 6  -- Destination network unknown */
			break;
		case ICMP_HOST_UNKNOWN:		/* 7  -- Destination host unknown */
			break;
		case ICMP_HOST_ISOLATED:	/* 8  -- Source host isolated */
			break;
		case ICMP_NET_ANO:			/* 9  -- Network administratively prohibited */
			break;
		case ICMP_HOST_ANO:			/* 10 -- Host administratively prohibited */
			break;
		case ICMP_NET_UNR_TOS:		/* 11 -- Network unreachable for ToS */
			break;
		case ICMP_HOST_UNR_TOS:		/* 12 -- Host unreachable for ToS */
			break;
		case ICMP_PKT_FILTERED:		/* 13 -- Packet filtered */
			break;
		case ICMP_PREC_VIOLATION:	/* 14 -- Precedence violation */
			break;
		case ICMP_PREC_CUTOFF:		/* 15 -- Precedence cut off */
			break;
	}
}

static void print_icmp_source_quench(const struct icmphdr *icmphdr) 
{
	int icmpcode = icmphdr->code;

	switch (icmpcode) {
		case 0:
			break;
	}
}

static void print_icmp_redirect(const struct icmphdr *icmphdr)
{
	int icmpcode_redirect = icmphdr->code;
	if (icmpcode_redirect > ICMP_REDIR_HOSTTOS) {
		(void)fprintf(stderr, "Unknown icmp redirect code %d\n", icmpcode_redirect);
		return;
	}

	switch (icmpcode_redirect) {
		case ICMP_REDIR_NET:		/* 0 */
			break;
		case ICMP_REDIR_HOST:		/* 1 */
			break;
		case ICMP_REDIR_NETTOS:		/* 2 */
			break;
		case ICMP_REDIR_HOSTTOS:	/* 3 */
			break;
	}
}

static void print_icmp_echo(const struct icmphdr *icmphdr, const uint8_t *optdata, size_t optdatalen)
{
//Echo or Echo Reply Message
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |     Code      |          Checksum             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Identifier          |        Sequence Number        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Data ...
//   +-+-+-+-+-

	int icmpcode_echo = icmphdr->code; 

	if (icmpcode_echo != 0) {
		(void)fprintf(stderr, "icmp echo message code must be is 0\n");
		return;
	}

printf("------------------------------------------------------> ping请求. code = %d\n", icmpcode_echo);
	/* 请求回显 -- ping请求 */
	printf("icmp code 0x%02x\n", icmpcode_echo);
	printf("Checksum 0x%04x\n", ntohs(icmphdr->checksum));
	printf("Identifier 0x%04x\n", ntohs(icmphdr->un.echo.id));
	printf("Sequence Number %hu\n", ntohs(icmphdr->un.echo.sequence));

	printf("Optdata:\n");
	size_t i;
	for (i = 0; i < optdatalen; i++) {
		printf("%02x ", optdata[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n");

#if 0
	switch (icmpcode) {
		case 0:	/* 请求回显 -- ping请求 */
			break;
	}
#endif
}

static void print_icmp_time_exceeded(const struct icmphdr *icmphdr)
{
	int icmpcode_time_exceeded = icmphdr->code;
	if (icmpcode_time_exceeded > ICMP_EXC_FRAGTIME) {
		(void)fprintf(stderr, "Unknown icmp time exceeded code %d\n", icmpcode_time_exceeded);
		return;
	}
	
	switch (icmpcode_time_exceeded) {
		case ICMP_EXC_TTL:	/* Time-to-live exceeded (Time to live exceeded in transit) ping -tx www.xx.com */
			break;
		case ICMP_EXC_FRAGTIME:
			break;
	}
}

static void print_icmp_parameterprob(const struct icmphdr *icmphdr)
{
	int icmpcode_parameterprob = icmphdr->code;
	if (icmpcode_parameterprob > ICMP_EXC_FRAGTIME) {
		(void)fprintf(stderr, "Unknown icmp parameterprob code %d\n", icmpcode_parameterprob);
		return;
	}

	switch (icmpcode_parameterprob) {
		case ICMP_EXC_TTL:
			break;
		case ICMP_EXC_FRAGTIME:
			break;
	}
}

static void print_icmp_timestamp(const struct icmphdr *icmphdr)
{
	int icmpcode = icmphdr->code;

	switch (icmpcode) {
		case 0:
			break;
	}
}

static void print_icmp_timestampreply(const struct icmphdr *icmphdr)
{
	int icmpcode = icmphdr->code;

	switch (icmpcode) {
		case 0:
			break;
	}
}

static void print_icmp_address(const struct icmphdr *icmphdr)
{
	int icmpcode = icmphdr->code;

	switch (icmpcode) {
		case 0:
			break;
	}
}

static void print_icmp_addressreply(const struct icmphdr *icmphdr)
{
	int icmpcode = icmphdr->code;

	switch (icmpcode) {
		case 0:
			break;
	}
}

#if 0
static const struct icmp_ {
	const char *des;
} icmp_type_str[NR_ICMP_TYPES] = {
	[0].des = "Echo Reply",
};
#else
static const char *icmp_type_str[NR_ICMP_TYPES+1] = {
/* 0 */	[ICMP_ECHOREPLY] = "Echo Reply",
/* 1 */	[1] = "Unused icmp type 1",	
/* 2 */	[2] = "Unused icmp type 2",
/* 3 */	[ICMP_DEST_UNREACH] = "Destination Unreachable",
/* 4 */	[ICMP_SOURCE_QUENCH] = "Source Quench",
/* 5 */	[ICMP_REDIRECT] = "Redirect (change route)",
/* 6 */	[6] = "Unused icmp type 6", 
/* 7 */	[7] = "Unused icmp type 7",
/* 8 */	[ICMP_ECHO] = "Echo Request",
/* 9 */	[9] = "Unused icmp type 9", 
/* 10 */[10] = "Unused icmp type 10", 
/* 11 */[ICMP_TIME_EXCEEDED] = "Time Exceeded",
/* 12 */[ICMP_PARAMETERPROB] = "Parameter Problem",
/* 13 */[ICMP_TIMESTAMP] = "Timestamp Request",
/* 14 */[ICMP_TIMESTAMPREPLY] = "Timestamp Reply",
/* 15 */[ICMP_INFO_REQUEST] = "Information Request",
/* 16 */[ICMP_INFO_REPLY] = "Information Reply",
/* 17 */[ICMP_ADDRESS] = "Address Mask Request",
/* 18 */[ICMP_ADDRESSREPLY] = "Address Mask Reply",
};
#endif

static void icmp_print(const u_char *icmphdr, size_t icmplen)
{
// http://blog.csdn.net/tigerjibo/article/details/7356936  ICMP报文分析
// http://www.cnblogs.com/scrat/archive/2012/08/02/2620163.html IP报文及ICMP报文结构原理

// RFC792
///usr/include/netinet/ip_icmp.h
//struct icmphdr
//{
//  u_int8_t type;                /* message type */
//  u_int8_t code;                /* type sub-code */
//  u_int16_t checksum;
//  union
//  {
//    struct
//    {
//      u_int16_t id;
//      u_int16_t sequence;
//    } echo;                     /* echo datagram */
//    u_int32_t   gateway;        /* gateway address */
//    struct
//    {
//      u_int16_t __glibc_reserved;
//      u_int16_t mtu;
//    } frag;                     /* path mtu discovery */
//  } un;
//};

	int icmptype;
	struct icmphdr icmpheader;

	(void)memcpy(&icmpheader, icmphdr, sizeof(icmpheader));

	icmptype = icmpheader.type;
	if (icmptype > NR_ICMP_TYPES) {
		(void)fprintf(stderr, "Unknown icmp type [%d]\n", icmptype);	
		return;
	}

	printf("icmp type 0x%02x[%s]\n", icmptype, icmp_type_str[icmptype]);

	switch (icmptype) {
		 /* /usr/include/netinet/ip_icmp.h */
		case ICMP_ECHOREPLY:		/* 0  -- Echo Reply */	
			print_icmp_echoreply(&icmpheader, icmphdr + sizeof(struct icmphdr), icmplen - sizeof(struct icmphdr));
			break;
		case ICMP_DEST_UNREACH:		/* 3  -- Destination Unreachable */
			print_icmp_dest_unreach(&icmpheader);
			break;
		case ICMP_SOURCE_QUENCH:	/* 4  -- Source Quench */
			print_icmp_source_quench(&icmpheader);
			break;
		case ICMP_REDIRECT:			/* 5  -- Redirect (change route) */
			print_icmp_redirect(&icmpheader);
			break;
		case ICMP_ECHO:				/* 8  -- Echo Request */
			print_icmp_echo(&icmpheader, icmphdr + sizeof(struct icmphdr), icmplen - sizeof(struct icmphdr));
			break;
		case ICMP_TIME_EXCEEDED:	/* 11 -- Time Exceeded */
			print_icmp_time_exceeded(&icmpheader);
			break;
		case ICMP_PARAMETERPROB:	/* 12 -- Parameter Problem */
			print_icmp_parameterprob(&icmpheader);
			break;
		case ICMP_TIMESTAMP:		/* 13 -- Timestamp Request */
			print_icmp_timestamp(&icmpheader);
			break;
		case ICMP_TIMESTAMPREPLY:	/* 14 -- Timestamp Reply */
			print_icmp_timestampreply(&icmpheader);
			break;
		case ICMP_INFO_REQUEST:		/* 15 -- 信息请求 - 作废不用 Information Request */
			break;
		case ICMP_INFO_REPLY:		/* 16 -- 信息应答 - 作废不用 Information Reply */
			break;
		case ICMP_ADDRESS:			/* 17 -- Address Mask Request */
			print_icmp_address(&icmpheader);
			break;
		case ICMP_ADDRESSREPLY:		/* 18 -- Address Mask Reply */
			print_icmp_addressreply(&icmpheader);
			break;
	}
}

static void igmp_print(const u_char *igmphdr)
{
}

static void ip_print(const u_char *iphdr, size_t iplen)
{
///usr/include/netinet/ip.h
//struct iphdr {
//#if defined(__LITTLE_ENDIAN_BITFIELD)
//    __u8    ihl:4,
//        version:4;
//#elif defined (__BIG_ENDIAN_BITFIELD)
//    __u8    version:4,
//        ihl:4;
//#else
//#error  "Please fix <asm/byteorder.h>"
//#endif
//    __u8    tos;
//    __be16  tot_len;
//    __be16  id;
//    __be16  frag_off;
//    __u8    ttl;
//    __u8    protocol;
//    __sum16 check;
//    __be32  saddr;
//    __be32  daddr;
//    /*The options start here. */
//};
//    0                   1                   2                   3   
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                    Example Internet Datagram Header
	int ihl;	/* internet header lenght */
	struct in_addr addr;
//	char buf[512];

	struct iphdr ipheader;

	(void)memcpy(&ipheader, iphdr, sizeof(ipheader));		
	
	printf("version: %u\n", ipheader.version);
	ihl = ipheader.ihl << 2;	/* ipheader.ihl * 4 */
	printf("header length: %u\n", ihl);
	printf("tos: %02x\n", ipheader.tos);
	printf("total length: %hu\n", ipheader.tot_len);
	addr.s_addr = ipheader.saddr;
	printf("source address: %s\n", inet_ntoa(addr));
//	printf("source address: %s\n", ip_addr((uint8_t *)&ipheader.saddr, buf, sizeof(buf)));
	addr.s_addr = ipheader.daddr;
	printf("destination address: %s\n", inet_ntoa(addr));
//	printf("destination address: %s\n", ip_addr((uint8_t *)&ipheader.daddr, buf, sizeof(buf)));

	switch (ipheader.protocol) {
		case IPPROTO_TCP:	/* netinet/in.h && linux/in.h */
			printf("protocol: TCP(%u)\n", ipheader.protocol);
			tcp_print(iphdr + ihl);
			break;
		case IPPROTO_UDP:
			printf("protocol: UDP(%u)\n", ipheader.protocol);
			udp_print(iphdr + ihl);
			break;
		case IPPROTO_ICMP:
			printf("protocol: ICMP(%u)\n", ipheader.protocol);
			icmp_print(iphdr + ihl, iplen - ihl);			
			break;
		case IPPROTO_IGMP:
			printf("protocol: IGMP(%u)\n", ipheader.protocol);
			igmp_print(iphdr + ihl);
			break; 
		default:
			(void)fprintf(stderr, "IP protocol [%u] is ignore\n", ipheader.protocol);	
			break;
	}
}

const static struct arp_proto_hrd {
	int 		arh_hrd;
	const char *arh_str;
} arp_proto_hrd[] = {
	{ARPHRD_NETROM, "ARPHRD_NETROM"},
	{ARPHRD_ETHER, "ARPHRD_ETHER"},
	{ARPHRD_EETHER, "ARPHRD_EETHER"},
	{ARPHRD_AX25, "ARPHRD_AX25"},
	{ARPHRD_PRONET, "ARPHRD_PRONET"},
	{ARPHRD_CHAOS, "ARPHRD_CHAOS"},
	{ARPHRD_IEEE802, "ARPHRD_IEEE802"},
	{ARPHRD_ARCNET, "ARPHRD_ARCNET"},
	{ARPHRD_APPLETLK, "ARPHRD_APPLETLK"},
	{ARPHRD_DLCI, "ARPHRD_DLCI"},
	{ARPHRD_ATM, "ARPHRD_ATM"},
	{ARPHRD_METRICOM, "ARPHRD_METRICOM"},
	{ARPHRD_IEEE1394, "ARPHRD_IEEE1394"},
	{ARPHRD_EUI64, "ARPHRD_EUI64"},
	{ARPHRD_INFINIBAND, "ARPHRD_INFINIBAND"},
};

static const char *arp_hrd_string(int hdr)
{
	int i;
	for (i = 0; i < sizeof(arp_proto_hrd)/sizeof(arp_proto_hrd[0]); i++) {
		if (arp_proto_hrd[i].arh_hrd == hdr) {
			return (arp_proto_hrd[i].arh_str);
		}
	}

	return (NULL);
}

const static struct __arp_prot_opcodes {
	int 			apo_op;
	const char *	apo_str;
} arp_prot_opcodes[] = {
	{ARPOP_REQUEST, "ARP_REQUEST"},
	{ARPOP_REPLY, "ARP_REPLY"},
	{ARPOP_RREQUEST, "RARP_REQUEST"},
	{ARPOP_RREPLY, "RARP_RREPLY"},
	{ARPOP_InREQUEST, "InARP_REQUEST"},
	{ARPOP_InREPLY, "InARP_RREPLY"},
	{ARPOP_NAK, "(ATM)ARP NAK"},
};

static const char *arp_opcodes_string(uint16_t op)
{
	int i;
	for (i = 0; i < sizeof(arp_prot_opcodes)/sizeof(arp_prot_opcodes[0]); i++) {
		if (arp_prot_opcodes[i].apo_op == op) {
			return (arp_prot_opcodes[i].apo_str);
		}
	}
	return (NULL);
}

static char *mac_addr(u_int8_t *mac, char *buf, size_t sz)
{
	int i;
	int ret = 0;

	for (i = 0; i < ETH_ALEN; i++) {
		ret += snprintf(buf + ret, sz - ret, "%02X:", mac[i]);
	}
	buf[strlen(buf)-1] = '\0';

	return (buf);
}

static void arp_print(const u_char *arphdr)
{
//http://www.cnblogs.com/laojie4321/archive/2012/04/12/2444187.html ARP协议的报文格式

///usr/include/netinet/if_ether.h
//struct  ether_arp {
//    struct  arphdr ea_hdr;      /* fixed-size header */
//    u_int8_t arp_sha[ETH_ALEN]; /* sender hardware address */
//    u_int8_t arp_spa[4];        /* sender protocol address */
//    u_int8_t arp_tha[ETH_ALEN]; /* target hardware address */
//    u_int8_t arp_tpa[4];        /* target protocol address */
//};

	char buf[512];
	struct ether_arp etharp;
	
	(void)memcpy(&etharp, arphdr, sizeof(etharp));

	printf("------------------------------------> ARP header\n");
	int hrd = ntohs(etharp.arp_hrd);
	printf("hardware address: %s(%hd)\n", arp_hrd_string(hrd), hrd);
	int proto = ntohs(etharp.arp_pro);
	printf("protocol address: %s(0x%04x)\n", eth_proto_string(proto), proto);
	printf("length of hardware address: %d\n", etharp.arp_hln);
	printf("Length of protocol address: %d\n", etharp.arp_pln);
	uint16_t op = ntohs(etharp.arp_op);
	printf("ARP opcode: %s(%hd)\n", arp_opcodes_string(op), op);
	printf("<------------------------------------ ARP header\n");

	printf("sender hardware address: %s\n", mac_addr(etharp.arp_sha, buf, sizeof(buf)));	
	printf("sender protocol address: %s\n", ip_addr(etharp.arp_spa, buf, sizeof(buf)));
	printf("target hardware address: %s\n", mac_addr(etharp.arp_tha, buf, sizeof(buf)));
	printf("target protocol address: %s\n", ip_addr(etharp.arp_tpa, buf, sizeof(buf)));

	switch (op) {
		case ARPOP_REQUEST:
			printf("%s问: ", ip_addr(etharp.arp_spa, buf, sizeof(buf)));
			printf("谁他娘的知道%s的MAC地址是多少啊?\n", ip_addr(etharp.arp_tpa, buf, sizeof(buf)));
//			printf("%s问: 谁他娘的知道%s的MAC地址是多少啊?\n", 
//						ip_addr(etharp.arp_spa, buf, sizeof(buf)),
//						ip_addr(etharp.arp_tpa, buf, sizeof(buf))); 
			break; 
		case ARPOP_REPLY:
			printf("%s", ip_addr(etharp.arp_spa, buf, sizeof(buf)));
			printf("回复%s: 特么我的MAC地址是(", ip_addr(etharp.arp_tpa, buf, sizeof(buf)));
			printf("%s)\n", mac_addr(etharp.arp_sha, buf, sizeof(buf)));
			break; 
		case ARPOP_RREQUEST:
			break; 
		case ARPOP_RREPLY:
			break; 
		case ARPOP_InREQUEST:
			break; 
		case ARPOP_InREPLY:
			break; 
		case ARPOP_NAK:
			break; 
	}
}


static void ethernet_capcallback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	int *id = (int *)args;

    int i;
    struct ether_header ether_hdr;//以太网字头
	char buf[512];

	// basic information
	printf("id: %d\n", ++(*id));
	printf("stamp: %s", ctime(&pkthdr->ts.tv_sec));
	printf("trulen = %u\n", pkthdr->len);	/* 包的长度 */
	printf("caplen = %u\n\n", pkthdr->caplen);	/* 实际抓取的长度 */
	// hex information
	for (i = 0; i < pkthdr->caplen; i++) {
//		printf("%02x ", packet[i]);
//		if ((i+1) % 16 == 0)	printf("\n");
	}
//	printf("\n");
    
	/* strict aliasing ??? */
	const struct ether_header *eh = (const struct ether_header *)packet;
	printf("ethertype = 0x%04xd\n", ntohs(eh->ether_type));

// /usr/include/net/ethernet.h
// /* 10Mb/s ethernet header */
// struct ether_header
// {
//   u_int8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
//   u_int8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
//   u_int16_t ether_type;             /* packet type ID field */
// } __attribute__ ((__packed__));
	// get ether header
	(void)memcpy(&ether_hdr, packet, sizeof(ether_hdr));
	// source ether addr  
	printf("SMAC: %s\n", mac_addr(ether_hdr.ether_shost, buf, sizeof(buf)));
	// destination eth addr
	printf("DMAC: %s\n", mac_addr(ether_hdr.ether_dhost, buf, sizeof(buf)));

	int ethertype = ntohs(ether_hdr.ether_type);
	printf("--------------------------------> ether type: %s(0x%04x)\n", eth_proto_string(ethertype), ethertype);

	switch (ethertype) {
		case ETHERTYPE_IP:	/* /usr/include/net/ethernet.h */
			ip_print(packet + sizeof(struct ether_header), pkthdr->caplen - sizeof(struct ether_header));
			break;
		case ETHERTYPE_ARP:
			arp_print(packet + sizeof(struct ether_header));
			break;
		case ETHERTYPE_IPV6:
			break;
		default:
			(void)fprintf(stderr, "Ethernet type [%x] is ignore\n", ethertype);
			return;	
	}
    
	printf("\n");
}

int main(int argc, char *argv[])
{
    char 				*device;
    char 				errbuf[PCAP_ERRBUF_SIZE];
    pcap_t 				*cap;
	int 				cnts = 0;
	pcap_handler 		capture_callback = NULL;
	struct bpf_program 	filter;
	int 				linktype;
    
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
		errx(EXIT_FAILURE, "pcap_lookupdev error: %s\n", errbuf);
    }
    
    cap = pcap_open_live(device, 65535, 0/*promiscous*/, 50/*ms*/, errbuf);
    if (cap == NULL) {
		errx(EXIT_FAILURE, "pcap_open_live error: %s\n", errbuf);
    }

	linktype = pcap_datalink(cap);
	switch (linktype) {
		case DLT_EN10MB:
			capture_callback = ethernet_capcallback; 
			break;
		case DLT_IPNET:
			break;
	}

//	if (pcap_compile(cap, &filter, "icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-echo", 0, 0) == -1) {
//	if (pcap_compile(cap, &filter, "icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply", 0, 0) == -1) {
//									proto     proto dir type                      proto dir type
	if (pcap_compile(cap, &filter, "icmp and (ether src host 00:aa:bb:cc:dd:ee or ether src host 00:e0:bb:bb:ee:ee)", 0, 0) == -1) {
//	if (pcap_compile(cap, &filter, "ip proto \\icmp and (ether src host 00:aa:bb:cc:dd:ee or ether src host 00:e0:bb:bb:ee:ee)", 0, 0) == -1) {
		errx(EXIT_FAILURE, "pcap_compile error: %s\n", pcap_geterr(cap));
	}
	if (pcap_setfilter(cap, &filter) == -1) {
		errx(EXIT_FAILURE, "pcap_setfilter error: %s\n", pcap_geterr(cap));
	}

    pcap_loop(cap, 0, capture_callback, (u_char *)&cnts);
    
    printf("Hello world\n");
	pcap_close(cap);

    return (0);
}
/* EOF */
