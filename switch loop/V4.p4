#include <core.p4>
#include <v1model.p4>
#include "include/header.p4"
#include "include/parser.p4"

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<32>>(32w5) traffic_limiter;

    action update_out_traffic_limit() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)standard_metadata.egress_port);
        meta.tmp.len = standard_metadata.packet_length << 3;
        meta.tmp.traffic = meta.tmp.traffic - meta.tmp.len;
        traffic_limiter.write((bit<32>)standard_metadata.egress_port, (bit<32>)meta.tmp.traffic);
    }

    action set_dmac(bit<48> dstAddr){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
    }

    action add_util() {
	    hdr.util.setValid();
	    util.id =  0x1234;
    }
    action write_sw_info() {
        traffic_limiter.read(util.handle_traffic, standard_metadata.egress_spec);
    }
    table dmac {
        key = {
            standard_metadata.egress_spec : exact;
        }
        actions = {
            set_dmac;
        }
        size = 16;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_out_traffic_limiter();
            dmac.apply();
            if(valid(util)){
        	    write_sw_info(); // write to util.handle_traffic
        	    if(tmp.tag == 1) // tag == 1, leaf switch
		    	    hdr.util.setInvalid();
		    }    
		    else{
        	    add_util();
        	    write_sw_info();
    	    }
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    register<bit<9>>(32w5) best_hop_port;
    register<bit<32>>(32w5) best_hop_traffic;
    register<bit<1>>(32w1) is_leaf;
    register<bit<9>>(32w2) port_range;
    register<bit<48>>(32w5) time_stamp;
    register<bit<32>>(32w5) traffic_limiter;
    action update_best_hop() {
        best_hop_traffic.write((bit<32>)0, (bit<32>)meta.tmp.traffic);
        best_hop_port.write((bit<32>)0, (bit<9>)meta.tmp.ingress_port);
        standard_metadata.egress_spec = meta.tmp.ingress_port;
    }
    action route(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action get_best_hop_info() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)meta.tmp.ingress_port);
        best_hop_traffic.read(meta.tmp.best_hop_traffic, (bit<32>)0);
        best_hop_port.read(meta.tmp.best_hop_port, (bit<32>)0);
    }
    action read_info() {
        port_range.read(meta.tmp.min_port_num, (bit<32>)0);
        port_range.read(meta.tmp.max_port_num, (bit<32>)1);
        is_leaf.read(meta.tmp.tag, (bit<32>)0);
        meta.tmp.ingress_port = standard_metadata.ingress_port;
    }
    action do_resubmit() {
        meta.tmp.resubmit_flag = 1w1;
        meta.tmp.ingress_port = 9w1;
        resubmit({ standard_metadata, meta.tmp });
    }
    action next_iteration() {
        meta.tmp.ingress_port = meta.tmp.ingress_port + 9w1;
        resubmit({ standard_metadata, meta.tmp });
    }
    action substract_to_max() {
        traffic_limiter.write((bit<32>)meta.tmp.ingress_port, (bit<32>)1600000);
    }
    action update_in_traffic_limit() {
        traffic_limiter.read(meta.tmp.traffic, (bit<32>)meta.tmp.ingress_port);
        time_stamp.read(meta.tmp.time_stamp, (bit<32>)0);
        meta.tmp.time_stamp = standard_metadata.ingress_global_timestamp - meta.tmp.time_stamp;
        meta.tmp.time_stamp = meta.tmp.time_stamp >> 30;
        meta.tmp.traffic = meta.tmp.traffic + (bit<32>)meta.tmp.time_stamp;
        traffic_limiter.write((bit<32>)meta.tmp.ingress_port, (bit<32>)meta.tmp.traffic);
        time_stamp.write((bit<32>)0, (bit<48>)standard_metadata.ingress_global_timestamp);
    }

    action record_sw_info() {
        traffic_limiter.write(tmp.ingress_port, util.handle_traffic);
    }

    table forward {
        actions = {
            route;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }

    table resubmit_new_pkt {
        key = {
            meta.tmp.resubmit_flag: exact;
        }
        actions = {
            do_resubmit;
        }
    }

    apply {
        if (meta.tmp.resubmit_flag == 1w0) {
            read_info();
        }
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {

                if(hdr.util.isValid() && tmp.resubmit_flag == 0)
                    record_sw_info(); // update info with util header

                update_in_traffic_limiter();

                if (meta.tmp.traffic > 32w1600000) {
                    substract_to_max();
                }

                resubmit_new_pkt.apply();

                if (meta.tmp.resubmit_flag == 1w1) {
                    if (meta.tmp.ingress_port <= meta.tmp.max_port_num && meta.tmp.ingress_port >= meta.tmp.min_port_num) {
                        
                        get_best_hop_info();
                        
                        if (meta.tmp.traffic >= meta.tmp.best_hop_traffic) {
                            update_best_hop();
                        }
                    }
                    
                    if (meta.tmp.ingress_port < meta.tmp.max_port_num) {
                        next_iteration();
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

control computeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
