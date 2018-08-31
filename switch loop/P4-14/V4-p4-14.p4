#include "include/headers.p4"
#include "include/parsers.p4"
#define MAX_TRAFFIC 1600000
#define LINK_BW 1000 //bps
/*
This is a register array that the key stands for ingress ports,
while maintaining the limitation of traffic in the entries.
all entries will be initialized with 1600byte*1000
*/
register traffic_limiter {
    width: 32;
    instance_count: 5;
}

// best_hop[0] stands for the path with maximum traffic limit
register best_hop_traffic {
    width: 32;
    instance_count: 5;
}
register best_hop_port {
    width: 9;
    instance_count: 5;
}

// to record the global_timestamp
register time_stamp {
    width: 48;
    instance_count: 5;
}

register port_range {
    width: 9;
    instance_count: 2;
}
register is_leaf {
    width: 1;
    instance_count: 1;
}
field_list resubmit_field {
    standard_metadata;
    intrinsic_metadata;
    tmp;
}
// update traffic_limiter for inbound traffic
action update_in_traffic_limit() {
    register_read(tmp.traffic, traffic_limiter, tmp.ingress_port);
    register_read(tmp.time_stamp, time_stamp, 0);
    subtract(tmp.time_stamp, intrinsic_metadata.ingress_global_timestamp, tmp.time_stamp);
    shift_left(tmp.time_stamp, tmp.time_stamp, 10);
    add_to_field(tmp.traffic,tmp.time_stamp);
    register_write(traffic_limiter, tmp.ingress_port, tmp.traffic); //register_name, index, value
    register_write(time_stamp, 0, intrinsic_metadata.ingress_global_timestamp); // record
}
table update_in_traffic_limiter {
    actions {
        update_in_traffic_limit;
    }
}

action update_out_traffic_limit(){
    register_read(tmp.traffic, traffic_limiter, standard_metadata.egress_port);
    shift_left(tmp.len, standard_metadata.packet_length, 3);
    subtract(tmp.traffic, tmp.traffic, tmp.len);
    register_write(traffic_limiter, standard_metadata.egress_port, tmp.traffic);
}
table update_out_traffic_limiter {
    actions {
        update_out_traffic_limit;
    }
}

action do_resubmit(){
    modify_field(tmp.resubmit_flag, 1);
    modify_field(tmp.ingress_port, 1);
    resubmit(resubmit_field);
}
table resubmit_new_pkt{
    reads {
        tmp.resubmit_flag : exact;
    }
    actions {
        do_resubmit;
    }
}

action next_iteration(){
    add_to_field(tmp.ingress_port, 1);
    resubmit(resubmit_field);
}
table start_next_iter{
    actions {
        next_iteration;
    }
}

action get_best_hop_info(){
    register_read(tmp.traffic, traffic_limiter, tmp.ingress_port);
    register_read(tmp.best_hop_traffic, best_hop_traffic, 0);
    register_read(tmp.best_hop_port, best_hop_port, 0);
}
table get_best_hop_info{
    actions {
        get_best_hop_info;
    }
}

action update_best_hop(){
    register_write(best_hop_traffic, 0 , tmp.traffic);
    register_write(best_hop_port, 0 , tmp.ingress_port);
    modify_field(standard_metadata.egress_spec, tmp.ingress_port);
}
table best_hop_update {
    actions {
        update_best_hop;
    }
}

action write_sw_info() {
    register_read(util.handle_traffic, traffic_limiter, standard_metadata.egress_spec);
}
table write_sw_info {
    actions {
        write_sw_info;
    }
}
table write_sw_info2 {
    actions {
        write_sw_info;
    }
}

action record_sw_info() {
    register_write(traffic_limiter, tmp.ingress_port, util.handle_traffic);
}
table record_sw_info{
    actions {
        record_sw_info;
    }
}

action adding_util() {
	add_header(util);
	modify_field(util.id, 0x1234);
}
table add_util {
	actions {
		adding_util;
	}
}

action removing_util() {
	remove_header(util);
}
table remove_util {
	actions {
		removing_util;
	}
}

action route(egress_spec) {
    modify_field(standard_metadata.egress_spec, egress_spec);
}
table forward {
    reads {
        ipv4.dstAddr: exact;
    }
    actions {
        route;
    }
    size: 1024;
}

action read_info() {
    register_read(tmp.min_port_num, port_range, 0);
    register_read(tmp.max_port_num, port_range, 1);
    register_read(tmp.tag, is_leaf, 0);
    modify_field(tmp.ingress_port, standard_metadata.ingress_port);
}
table read_info {
    actions {
        read_info;
    }
}

action substract_to_max() {
    register_write(traffic_limiter, tmp.ingress_port, MAX_TRAFFIC);
}
table substract_to_max {
    actions {
    	substract_to_max;
	}
}
control ingress {
    if(tmp.resubmit_flag == 0)
        apply(read_info);
    if(valid(ipv4)){
        if(valid(tcp)){
            if(valid(util) && tmp.resubmit_flag == 0)
                apply(record_sw_info); // update info with util header
        	
		    apply(update_in_traffic_limiter); // inbound traffic, update the corresponding register(increase)
			if(tmp.traffic > MAX_TRAFFIC)
				apply(substract_to_max);

	        apply(resubmit_new_pkt);
            if(tmp.resubmit_flag == 1){
                // to handle resubmitted pkt in order to get the best next hop
                if(tmp.ingress_port <= tmp.max_port_num && tmp.ingress_port >= tmp.min_port_num){
                    apply(get_best_hop_info);
                    if(tmp.traffic >= tmp.best_hop_traffic){
                        apply(best_hop_update);
                    }
                }
		        if(tmp.ingress_port < tmp.max_port_num)
                    apply(start_next_iter);
                else
                    apply(forward);
            }
        }
    }
}

control egress {
    if(valid(ipv4)){
    	apply(update_out_traffic_limiter); // outbound traffic, update the corresponding traffic(decrease)
		if(valid(util)){
        	apply(write_sw_info); // write to util.handle_traffic
        	if(tmp.tag == 1) // tag == 1, leaf switch
		    	apply(remove_util);
		}    
		else{
        	apply(add_util);
        	apply(write_sw_info2);
    	}
	}
}
