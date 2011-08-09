#include <iostream>
#include <string>

using namespace std;

/* Netflow stuff */

/*  NetFlow Export Version 9 Header Format  */
struct struct_header_v9 {
  u_int16_t version;		/* version = 9 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  u_int32_t source_id;		/* Source id */
};

/* NetFlow Export version 1 */
struct struct_export_v1 {
  struct in_addr srcaddr;	/* Source IP Address */
  struct in_addr dstaddr;	/* Destination IP Address */
  struct in_addr nexthop;	/* Next hop router's IP Address */
  u_int16_t input;		/* Input interface index */
  u_int16_t output;    		/* Output interface index */
  u_int32_t dPkts;      	/* Packets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t dOctets;    	/* Octets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t First;      	/* SysUptime at start of flow */
  u_int32_t Last;       	/* and of last packet of the flow */
  u_int16_t srcport;   		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;   		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;       		/* pad to word boundary */
  unsigned char prot;           /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;            /* IP Type-of-Service */
  unsigned char pad_2[8];	/* pad to word boundary */
};

/* NetFlow Export version 5 */
struct struct_export_v5 {
  struct in_addr srcaddr;       /* Source IP Address */
  struct in_addr dstaddr;       /* Destination IP Address */
  struct in_addr nexthop;       /* Next hop router's IP Address */
  u_int16_t input;   		/* Input interface index */
  u_int16_t output;  		/* Output interface index */
  u_int32_t dPkts;    		/* Packets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t dOctets;  		/* Octets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t First;    		/* SysUptime at start of flow */
  u_int32_t Last;     		/* and of last packet of the flow */
  u_int16_t srcport; 		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport; 		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  unsigned char pad;          	/* pad to word boundary */
  unsigned char tcp_flags;    	/* Cumulative OR of tcp flags */
  unsigned char prot;         	/* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;          	/* IP Type-of-Service */
  u_int16_t src_as;  		/* source peer/origin Autonomous System */
  u_int16_t dst_as;  		/* dst peer/origin Autonomous System */
  unsigned char src_mask;       /* source route's mask bits */ 
  unsigned char dst_mask;       /* destination route's mask bits */
  u_int16_t pad_1;   		/* pad to word boundary */
};

/* NetFlow Export version 7 */
struct struct_export_v7 {
  u_int32_t srcaddr;		/* Source IP Address */
  u_int32_t dstaddr;		/* Destination IP Address */
  u_int32_t nexthop;		/* Next hop router's IP Address */
  u_int16_t input;		/* Input interface index */
  u_int16_t output;		/* Output interface index */
  u_int32_t dPkts;		/* Packets sent in Duration */
  u_int32_t dOctets;		/* Octets sent in Duration. */
  u_int32_t First;		/* SysUptime at start of flow */
  u_int32_t Last;		/* and of last packet of flow */
  u_int16_t srcport;		/* TCP/UDP source port number or equivalent */
  u_int16_t dstport;		/* TCP/UDP destination port number or equiv */
  u_int8_t  pad;
  u_int8_t  tcp_flags;		/* Cumulative OR of tcp flags */
  u_int8_t  prot;		/* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  u_int8_t  tos;		/* IP Type-of-Service */
  u_int16_t src_as;		/* originating AS of source address */
  u_int16_t dst_as;		/* originating AS of destination address */
  u_int8_t  src_mask;		/* source address prefix mask bits */
  u_int8_t  dst_mask;		/* destination address prefix mask bits */
  u_int16_t drops;
  u_int32_t router_sc;		/* Router which is shortcut by switch */
};

/* NetFlow Export version 9 */
struct template_field_v9 {
  u_int16_t type;
  u_int16_t len;
}; 

struct template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t num;
};

struct options_template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t scope_len;
  u_int16_t option_len;
};

struct data_hdr_v9 /*flowset_hdr_v9*/ {
  u_int16_t flow_id; /* == 0: template; == 1: options template; >= 256: data */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 9996
#define NETFLOW_MSG_SIZE 1550
#define TEMPLATE_CACHE_ENTRIES 20

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

#define NF_AS_KEEP 0 /* Keep AS numbers in NetFlow packets */
#define NF_AS_NEW 1 /* ignore ASN from NetFlow and generate from network files */ 
#define NF_AS_BGP 2 /* ignore ASN from NetFlow and generate from BGP peerings */

#define NF_NET_COMPAT	0x00000000 /* Backward compatibility selection */
#define NF_NET_KEEP	0x00000001 /* Determine IP network prefixes from NetFlow data */
#define NF_NET_NEW	0x00000002 /* Determine IP network prefixes from network files */
#define NF_NET_BGP	0x00000004 /* Determine IP network prefixes from BGP peerings */
#define NF_NET_STATIC	0x00000008 /* Determine IP network prefixes from static mask */

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
#define NF9_MAX_DEFINED_FIELD		80

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
#define NF9_FLOWS			3
#define NF9_L4_PROTOCOL			4
#define NF9_SRC_TOS                     5
#define NF9_TCP_FLAGS                   6
#define NF9_L4_SRC_PORT                 7
#define NF9_IPV4_SRC_ADDR               8
#define NF9_SRC_MASK                    9
#define NF9_INPUT_SNMP                  10
#define NF9_L4_DST_PORT                 11
#define NF9_IPV4_DST_ADDR               12
#define NF9_DST_MASK                    13
#define NF9_OUTPUT_SNMP                 14
#define NF9_IPV4_NEXT_HOP               15
#define NF9_SRC_AS                      16
#define NF9_DST_AS                      17
#define NF9_BGP_IPV4_NEXT_HOP		18
#define NF9_MUL_DST_PKTS                19
#define NF9_MUL_DST_BYTES               20
/* ... */
#define NF9_LAST_SWITCHED               21
#define NF9_FIRST_SWITCHED              22
/* ... */
#define NF9_IPV6_SRC_ADDR               27
#define NF9_IPV6_DST_ADDR               28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
#define NF9_ICMP_TYPE                   32
/* ... */
#define NF9_ENGINE_TYPE                 38
#define NF9_ENGINE_ID                   39
/* ... */
#define NF9_SRC_MAC                     56
#define NF9_DST_MAC                     57
#define NF9_SRC_VLAN                    58
#define NF9_DST_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION         60
#define NF9_DIRECTION                   61
#define NF9_IPV6_NEXT_HOP		62
#define NF9_BGP_IPV6_NEXT_HOP		63
/* ... */
#define NF9_MPLS_LABEL_1		70
#define NF9_MPLS_LABEL_2		71
#define NF9_MPLS_LABEL_3		72
#define NF9_MPLS_LABEL_4		73
#define NF9_MPLS_LABEL_5		74
#define NF9_MPLS_LABEL_6		75
#define NF9_MPLS_LABEL_7		76
#define NF9_MPLS_LABEL_8		77
#define NF9_MPLS_LABEL_9		78
#define NF9_MPLS_LABEL_10		79
/* ... */
#define NF9_CUST_CLASS			200
#define NF9_CUST_TAG			201
#define NF9_CUST_TAG2			202

#define NF9_FTYPE_IPV4			0
#define NF9_FTYPE_IPV6			1
#define NF9_FTYPE_VLAN			5
#define NF9_FTYPE_VLAN_IPV4		5
#define NF9_FTYPE_VLAN_IPV6		6
#define NF9_FTYPE_MPLS			10
#define NF9_FTYPE_MPLS_IPV4		10
#define NF9_FTYPE_MPLS_IPV6		11
#define NF9_FTYPE_VLAN_MPLS		15	
#define NF9_FTYPE_VLAN_MPLS_IPV4	15
#define NF9_FTYPE_VLAN_MPLS_IPV6	16

/* Sampling */
#define NF9_SAMPLING_INTERVAL		34
#define NF9_SAMPLING_ALGORITHM		35
#define NF9_FLOW_SAMPLER_ID		48
#define NF9_FLOW_SAMPLER_MODE		49
#define NF9_FLOW_SAMPLER_INTERVAL	50

#define NF9_OPT_SCOPE_SYSTEM		1
#define NF9_OPT_SCOPE_IF		2
#define NF9_OPT_SCOPE_LC		3
#define NF9_OPT_SCOPE_CACHE		4
#define NF9_OPT_SCOPE_TPL		5

/* Ordered Template field */
struct otpl_field {
  u_int16_t type;
  u_int16_t len;
};

struct host_addr {
  u_int8_t family;
  union {
    struct in_addr ipv4;
#if defined ENABLE_IPV6
    struct in6_addr ipv6;
#endif
  } address;
};



struct template_cache_entry {
  u_int16_t template_id;		/* template ID */
  u_int16_t template_type;		/* Data = 0, Options = 1 */
  u_int16_t num;			/* number of fields described into template */ 
  u_int16_t len;			/* total length of the described flowset */
  char table_name[24];
  //char template_entry[1500];		/* 除去Template ID和Field Count字段的模板实体 */
  struct otpl_field tpl_entry[NF9_MAX_DEFINED_FIELD];
  //struct template_cache_entry *next;	
};

struct template_cache {
  u_int16_t num;
  struct template_cache_entry c[TEMPLATE_CACHE_ENTRIES];
};



typedef void (*v8_filter_handler)(struct packet_ptrs *, void *);
struct v8_handler_entry {
  u_int8_t max_flows;
  u_int8_t exp_size;
  v8_filter_handler fh;
};

/* functions */

void process_v9_packet(unsigned char *pkt, int len);
