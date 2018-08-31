#ifndef __HEADERS__
#define __HEADERS__

header_type ethernet_t {
    fields{
        dstAddr: 48;
        srcAddr: 48;
        etherType: 16;
    }
}

header_type ipv4_t {
    fields{
        version: 4;
        ihl: 4;
        diffserv: 8;
        len: 16;
        identification_: 16;
        flags: 3;
        fragOffset: 13;
        ttl: 8;
        protocol: 8;
        hdr_checksum: 16;
        srcAddr: 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields{
        srcPort: 16;
        dstPort: 16;
        seqNo: 32;
        ackNo: 32;
        dataOffset: 4;
        res: 3;
        ecn: 3;
        ctrl: 6;
        window: 16;
        checksum: 16;
        urgentPtr: 16;
    }
}

header_type udp_t {
    fields{
        srcPort: 16;
        dstPort: 16;
        length_: 16;
        checksum: 16;
    }
}

header_type util_t {
    fields {
        id: 16;
        handle_traffic: 32;
    }
}

header_type tmp_metadata_t {
	fields {
		traffic: 32;
        best_hop_traffic: 32;
        best_hop_port: 9;
        time_stamp: 48;
        len: 32;
        max_port_num: 9;
        min_port_num: 9;
        ingress_port: 9;
        tag: 1;
	    resubmit_flag: 1;
	}
}
header_type intrinsic_metadata_t {
	fields {
		ingress_global_timestamp : 48;
		lf_field_list : 8;
		mcast_grp : 16;
		egress_rid : 16;
		resubmit_flag : 8;
		recirculate_flag : 8;
	}
}

metadata intrinsic_metadata_t intrinsic_metadata;
metadata tmp_metadata_t tmp;
header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;
header util_t util;

#endif
