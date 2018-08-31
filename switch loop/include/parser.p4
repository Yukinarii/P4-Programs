#ifndef __PARSERS__
#define __PARSERS__

#include "header.p4"

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".parse_util") state parse_util {
        packet.extract(hdr.util);
        transition parse_ethernet;
    }
    @name(".start") state start {
        transition select((packet.lookahead<bit<16>>())[15:0]) {
            16w0x1234: parse_util;
            default: parse_ethernet;
        }
    }
}

#endif
