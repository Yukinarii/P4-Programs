#include <core.p4>
#include <v1model.p4>

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<8>  lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<8>  resubmit_flag;
    bit<8>  recirculate_flag;
}

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
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> identification_;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
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
    @name(".intrinsic_metadata") 
    intrinsic_metadata_t intrinsic_metadata;
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

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".traffic_limiter") register<bit<32>>(32w5) traffic_limiter;

    @name(".update_out_traffic_limit") action update_out_traffic_limit() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)standard_metadata.egress_port);
        meta.tmp.len = standard_metadata.packet_length << 3;
        meta.tmp.traffic = meta.tmp.traffic - meta.tmp.len;
        traffic_limiter.write((bit<32>)standard_metadata.egress_port, (bit<32>)meta.tmp.traffic);
    }
    @name(".update_out_traffic_limiter") table update_out_traffic_limiter {
        actions = {
            update_out_traffic_limit;
        }
    }
    apply {
        if (hdr.ipv4.isValid()) {
            update_out_traffic_limiter.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".best_hop_port") register<bit<9>>(32w5) best_hop_port;
    @name(".best_hop_traffic") register<bit<32>>(32w5) best_hop_traffic;
    @name(".is_leaf") register<bit<1>>(32w1) is_leaf;
    @name(".port_range") register<bit<9>>(32w2) port_range;
    @name(".time_stamp") register<bit<48>>(32w5) time_stamp;
    @name(".traffic_limiter") register<bit<32>>(32w5) traffic_limiter;
    @name(".update_best_hop") action update_best_hop() {
        best_hop_traffic.write((bit<32>)0, (bit<32>)meta.tmp.traffic);
        best_hop_port.write((bit<32>)0, (bit<9>)meta.tmp.ingress_port);
        standard_metadata.egress_spec = meta.tmp.ingress_port;
    }
    @name(".route") action route(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
    }
    @name(".get_best_hop_info") action get_best_hop_info() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)meta.tmp.ingress_port);
        best_hop_traffic.read(meta.tmp.best_hop_traffic, (bit<32>)0);
        best_hop_port.read(meta.tmp.best_hop_port, (bit<32>)0);
    }
    @name(".read_info") action read_info() {
        port_range.read(meta.tmp.min_port_num, (bit<32>)0);
        port_range.read(meta.tmp.max_port_num, (bit<32>)1);
        is_leaf.read(meta.tmp.tag, (bit<32>)0);
        meta.tmp.ingress_port = standard_metadata.ingress_port;
    }
    @name(".do_resubmit") action do_resubmit() {
        meta.tmp.resubmit_flag = 1w1;
        meta.tmp.ingress_port = 9w1;
        resubmit({ standard_metadata, meta.intrinsic_metadata, meta.tmp });
    }
    @name(".next_iteration") action next_iteration() {
        meta.tmp.ingress_port = meta.tmp.ingress_port + 9w1;
        resubmit({ standard_metadata, meta.intrinsic_metadata, meta.tmp });
    }
    @name(".substract_to_max") action substract_to_max() {
        traffic_limiter.write((bit<32>)meta.tmp.ingress_port, (bit<32>)1600000);
    }
    @name(".update_in_traffic_limit") action update_in_traffic_limit() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)meta.tmp.ingress_port);
        time_stamp.read(meta.tmp.time_stamp, (bit<32>)0);
        meta.tmp.time_stamp = meta.intrinsic_metadata.ingress_global_timestamp - meta.tmp.time_stamp;
        meta.tmp.time_stamp = meta.tmp.time_stamp << 10;
        meta.tmp.traffic = meta.tmp.traffic + (bit<32>)meta.tmp.time_stamp;
        traffic_limiter.write((bit<32>)meta.tmp.ingress_port, (bit<32>)meta.tmp.traffic);
        time_stamp.write((bit<32>)0, (bit<48>)meta.intrinsic_metadata.ingress_global_timestamp);
    }
    @name(".best_hop_update") table best_hop_update {
        actions = {
            update_best_hop;
        }
    }
    @name(".forward") table forward {
        actions = {
            route;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = 1024;
    }
    @name(".get_best_hop_info") table get_best_hop_info_0 {
        actions = {
            get_best_hop_info;
        }
    }
    @name(".read_info") table read_info_0 {
        actions = {
            read_info;
        }
    }
    @name(".resubmit_new_pkt") table resubmit_new_pkt {
        actions = {
            do_resubmit;
        }
        key = {
            meta.tmp.resubmit_flag: exact;
        }
    }
    @name(".start_next_iter") table start_next_iter {
        actions = {
            next_iteration;
        }
    }
    @name(".substract_to_max") table substract_to_max_0 {
        actions = {
            substract_to_max;
        }
    }
    @name(".update_in_traffic_limiter") table update_in_traffic_limiter {
        actions = {
            update_in_traffic_limit;
        }
    }
    apply {
        if (meta.tmp.resubmit_flag == 1w0) {
            read_info_0.apply();
        }
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
                update_in_traffic_limiter.apply();
                if (meta.tmp.traffic > 32w1600000) {
                    substract_to_max_0.apply();
                }
                resubmit_new_pkt.apply();
                if (meta.tmp.resubmit_flag == 1w1) {
                    if (meta.tmp.ingress_port <= meta.tmp.max_port_num && meta.tmp.ingress_port >= meta.tmp.min_port_num) {
                        get_best_hop_info_0.apply();
                        if (meta.tmp.traffic >= meta.tmp.best_hop_traffic) {
                            best_hop_update.apply();
                        }
                    }
                    if (meta.tmp.ingress_port < meta.tmp.max_port_num) {
                        start_next_iter.apply();
                    }
                    else {
                        forward.apply();
                    }
                }
            }
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.util);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
