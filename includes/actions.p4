action set_tcp_ports() {
    modify_field(l4.sport, tcp.srcPort);
    modify_field(l4.dport, tcp.dstPort);
}

action set_udp_ports() {
    modify_field(l4.sport, udp.srcPort);
    modify_field(l4.dport, udp.dstPort);
}

action add_score(score_value) {
	add_to_field(score_metadata.score, score_value);
}

action set_x(score_value,x) {
	add_to_field(score_metadata.score, score_value);
	modify_field(factor.x, x);
}


action set_threshold(high,low) {
	modify_field(threshold.T_high, high);
	modify_field(threshold.T_low, low);
}

primitive_action set_x_factor();

action x_factor() {
	set_x_factor();
}


action do_pdf() {
	count(pdf_counter,score_metadata.score);        
}

field_list copy_to_cpu_fields {
	score_metadata;
	factor;
	threshold;
	tcp;
}

action send_digest() {
	generate_digest(0,copy_to_cpu_fields);
}

action send_out() {
    split();
}

primitive_action split();

action _drop() {
	drop();
}

action _nop() {
	
}

action set_counting_flag(flag) {
    modify_field(counting_flag.flag, flag);
}

action set_score_flag(flag) {
    modify_field(score_flag.flag, flag);
}
