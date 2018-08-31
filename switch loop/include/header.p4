#ifndef __HEADERS__
#define __HEADERS__

struct tmp_metadata_t {
    bit<32> traffic;
    bit<32> best_hop_traffic;
    bit<9>  best_hop_port;
    bit<48> time_stamp;
    bit<32> len;
    bit<9>  max_port_num;
    bit<9>  min_port_num;
    bit<9>  ingress_port;
    bit<1>  tag;
    bit<1>  resubmit_flag;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header util_t {
    bit<16> id;
    bit<32> handle_traffic;
}

struct metadata {
    @name(".tmp") 
    tmp_metadata_t       tmp;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
    @name(".util") 
    util_t     util;
}

#endif
