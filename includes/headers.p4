header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ipv4_t ipv4;

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp;

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header udp_t udp;

// Metadata to hold port numbers for both TCP and UDP
header_type l4_t {
    fields {
        sport: 16;
        dport: 16;
    }
}

metadata l4_t l4;


header_type score_metadata_t {
    fields {
        score: 16;
	score_quantified: 16;
    }
}

metadata score_metadata_t score_metadata;

header_type counting_flag_t {
    fields {
        flag: 16;
    }
}

metadata counting_flag_t counting_flag;

header_type score_flag_t {
    fields {
        flag: 16;
    }
}

metadata score_flag_t score_flag;

header_type factor_t {
    fields {
        x: 16;
    }
}

metadata factor_t factor;

header_type threshold_t {
    fields {
        T_high:32;
        T_low:32;
    }   
}   

metadata threshold_t threshold;
