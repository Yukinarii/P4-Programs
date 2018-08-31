#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"

parser start {
	return select(current(0, 16)) {
	    0x1234: parse_util;
	default: parse_ethernet;
	}
}

parser parse_util{
	extract(util);
	return parse_ethernet;
}

parser parse_ethernet{
	extract(ethernet);
	return select(ethernet.etherType) {
		0x0800: parse_ipv4;
	}
}

parser parse_ipv4{
	extract(ipv4);
	return select(ipv4.protocol) {
		0x6: parse_tcp;
		0x11: parse_udp;
		default: ingress;
	}
}

parser parse_udp{
	extract(udp);
	return ingress;
}

parser parse_tcp{
	extract(tcp);
	return ingress;
}

#endif
