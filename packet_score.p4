#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/actions.p4"

table l4_ports {
	reads {
		ipv4.protocol: exact;
	}
	actions {
		set_tcp_ports;
		set_udp_ports;
	}
	max_size:3;
}

table switch_counting_flag {
    actions {
        set_counting_flag;
    }
}

table switch_score_flag {
    actions {
        set_score_flag;
    }
}







counter src_ip_counter_0 {
	type: packets;
	direct: src_ip_0;
}

table src_ip_0 {
	reads {
		ipv4.srcAddr: lpm;
	}
	actions {
		_nop;
	}
	max_size:2999;
}

counter dst_ip_counter_0 {
	type: packets;
	direct: dst_ip_0;
}

table dst_ip_0 {
	reads {
		ipv4.dstAddr: lpm;
	}
	actions {
		_nop;
	}
	max_size:2999;
}

counter proto_counter_0 {
	type: packets;
	direct: proto_0;
}

table proto_0 {
	reads {
		ipv4.protocol: ternary;
	}
	actions {
		_nop;
	}
	max_size:49;
}

counter src_port_counter_0 {
	type: packets;
	direct: src_port_0;
}

table src_port_0 {
	reads {
		tcp.srcPort: range;
	}
	actions {
		_nop;
	}
	max_size:499;
}

counter dst_port_counter_0 {
	type: packets;
	direct: dst_port_0;
}

table dst_port_0 {
	reads {
		tcp.dstPort: range;
	}
	actions {
		_nop;
	}
	max_size:499;
}












counter src_ip_counter_1 {
	type: packets;
	direct: src_ip_1;
}

table src_ip_1 {
	reads {
		ipv4.srcAddr: lpm;
	}
	actions {
		_nop;
	}
	max_size:2999;
}

counter dst_ip_counter_1 {
	type: packets;
	direct: dst_ip_1;
}

table dst_ip_1 {
	reads {
		ipv4.dstAddr: lpm;
	}
	actions {
		_nop;
	}
	max_size:2999;
}

counter proto_counter_1 {
	type: packets;
	direct: proto_1;
}

table proto_1 {
	reads {
		ipv4.protocol: ternary;
	}
	actions {
		_nop;
	}
	max_size:49;
}

counter src_port_counter_1 {
	type: packets;
	direct: src_port_1;
}

table src_port_1 {
	reads {
		l4.sport: range;
	}
	actions {
		_nop;
	}
	max_size:499;
}

counter dst_port_counter_1 {
	type: packets;
	direct: dst_port_1;
}

table dst_port_1 {
	reads {
		l4.dport: range;
	}
	actions {
		_nop;
	}
	max_size:499;
}












table src_ip_score_0 {
	reads {
		ipv4.srcAddr: lpm;
	}
	actions {
		add_score;
	}
	max_size:2999;
}

table dst_ip_score_0 {
	reads {
		ipv4.dstAddr: lpm;
	}
	actions {
		add_score;
	}
	max_size:2999;
}

table proto_score_0 {
	reads {
		ipv4.protocol: ternary;
	}
	actions {
		add_score;
	}
	max_size:49;
}

table src_port_score_0 {
	reads {
		tcp.srcPort: range;
	}
	actions {
		add_score;
	}
	max_size:499;
}

table dst_port_score_0 {
	reads {
		tcp.dstPort: range;
	}
	actions {
		add_score;
	}
	max_size:499;
}






table src_ip_score_1 {
	reads {
		ipv4.srcAddr: lpm;
	}
	actions {
		add_score;
	}
	max_size:2999;
}

table dst_ip_score_1 {
	reads {
		ipv4.dstAddr: lpm;
	}
	actions {
		add_score;
	}
	max_size:2999;
}

table proto_score_1 {
	reads {
		ipv4.protocol: ternary;
	}
	actions {
		add_score;
	}
	max_size:49;
}

table src_port_score_1 {
	reads {
		l4.sport: range;
	}
	actions {
		add_score;
	}
	max_size:499;
}

table dst_port_score_1 {
	reads {
		l4.dport: range;
	}
	actions {
		add_score;
	}
	max_size:499;
}









table sum_up {
	actions {
		set_x;
	}
}

table set_thresh {
	actions {
		set_threshold;
	}
}

table discrete {
	actions {
		x_factor;
	}
}

counter pdf_counter {
	type: packets;
	instance_count: 10000;
}

table PDF {
	actions {
		do_pdf;
	}
}

table digest {
	actions {
		send_digest;
	}
}

counter n_flow_counter {
        type: packets;
        direct: classify;
}

table classify {
	actions {
		send_out;
	}
}

control ingress {
	apply(l4_ports);

    apply(switch_counting_flag);
    if (counting_flag.flag == 0) {
        apply(src_ip_0);
	    apply(dst_ip_0);
	    apply(proto_0);
	    apply(src_port_0);
	    apply(dst_port_0);
    }



    if (counting_flag.flag == 1) {
        apply(src_ip_1);
	    apply(dst_ip_1);
	    apply(proto_1);
	    apply(src_port_1);
	    apply(dst_port_1);
    }



    apply(switch_score_flag);
    if (score_flag.flag == 0) {
	    apply(src_ip_score_0);
	    apply(dst_ip_score_0);
	    apply(proto_score_0);
	    apply(src_port_score_0);
	    apply(dst_port_score_0);
	}



	if (score_flag.flag == 1) {
	    apply(src_ip_score_1);
	    apply(dst_ip_score_1);
	    apply(proto_score_1);
	    apply(src_port_score_1);
	    apply(dst_port_score_1);
	}



	apply(sum_up);
	apply(set_thresh);
	apply(discrete);
	apply(PDF);
	apply(digest);
	apply(classify);
}

control egress {
	
}
