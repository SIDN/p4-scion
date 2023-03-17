/* -*- P4_16 -*- */

/* 
 * Copyright (c) 2021, SIDN Labs
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined DISABLE_IPV4 && defined DISABLE_IPV6
#error "Disabling both IPv4 and IPv6 support is not supported"
#endif

#include <core.p4>
#include <tna.p4>

#include "headers/common.p4"
#include "headers/scion.p4"


/*************************************************************************
*********************** C O N S T A N T S  *******************************
*************************************************************************/

#define PORT_CPU 64

/*************************************************************************
************************* H E A D E R S  *********************************
*************************************************************************/

header scion_cpu_t {
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
}

header scion_jump_data_t {
	bit<96>		data;
}

header scion_jump_data_2_t {
	bit<(2*96)>	data;
}

header scion_jump_data_3_t {
	bit<(3*96)>	data;
}

header scion_jump_data_4_t {
	bit<(4*96)>	data;
}

header scion_jump_data_8_t {
	bit<(8*96)>	data;
}

header scion_jump_data_16_t {
	bit<(16*96)>	data;
}

struct header_t {
	scion_cpu_t		scion_cpu;
	ethernet_t		ethernet;
#ifndef DISABLE_IPV4
	ipv4_t			ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
	ipv6_t			ipv6;
#endif /* DISABLE_IPV6 */
	udp_t			udp;
	scion_common_t		scion_common;
	scion_addr_common_t	scion_addr_common;
	scion_addr_host_32_t	scion_addr_dst_host_32;
	scion_addr_host_32_t	scion_addr_dst_host_32_2;
	scion_addr_host_32_t	scion_addr_dst_host_32_3;
	scion_addr_host_128_t	scion_addr_dst_host_128;
	scion_addr_host_32_t	scion_addr_src_host_32;
	scion_addr_host_32_t	scion_addr_src_host_32_2;
	scion_addr_host_32_t	scion_addr_src_host_32_3;
	scion_addr_host_128_t	scion_addr_src_host_128;
	scion_path_meta_t	scion_path_meta;
	scion_info_field_t	scion_info_field_0;
	scion_info_field_t	scion_info_field_1;
	scion_info_field_t	scion_info_field_2;
	scion_jump_data_16_t	scion_jump_16;
	scion_jump_data_8_t	scion_jump_8;
	scion_jump_data_4_t	scion_jump_4;
	scion_jump_data_3_t	scion_jump_3;
	scion_jump_data_2_t	scion_jump_2;
	scion_jump_data_t	scion_jump_1;
	scion_hop_field_t	scion_hop_field_0;
	scion_hop_field_t	scion_hop_field_1;
}

struct metadata_t {
	bit<1>	direction;
	bit<16> segId;
	bit<16> nextSegId;
	bit<32> timestamp;
	bit<16> ingress;
	bit<16> egress;
	bit<6>	segLen;
	bit<6>	currHF;
	bit<6>	currHF2;
	bit<2>	nextINF;
	bit<6>	seg1Len;
	bit<16>	udp_checksum_tmp;
	bit<16> payload_len;
}

/*************************************************************************
***********************  P A R S E R  ************************************
*************************************************************************/

parser ScionIngressParser(
		packet_in packet,
		out header_t hdr,
		out metadata_t meta,
		out ingress_intrinsic_metadata_t ig_intr_md) {
	Checksum() udp_checksum;

	state start {
		// Extract metadata and skip over recirculation info
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);

		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
#ifndef DISABLE_IPV4
			EtherType.IPV4: ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
			EtherType.IPV6: ipv6;
#endif /* DISABLE_IPV6 */
		}
	}

#ifndef DISABLE_IPV4
	state ipv4 {
		packet.extract(hdr.ipv4);

		udp_checksum.subtract({hdr.ipv4.srcAddr});
		udp_checksum.subtract({hdr.ipv4.dstAddr});

		transition scion;
	}
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
	state ipv6 {
		packet.extract(hdr.ipv6);
		udp_checksum.subtract({hdr.ipv6.srcAddr});
		udp_checksum.subtract({hdr.ipv6.dstAddr});
		transition scion;
	}
#endif /* DISABLE_IPV6 */

	state scion {
		packet.extract(hdr.udp);
		udp_checksum.subtract({hdr.udp.srcPort, hdr.udp.dstPort});
		udp_checksum.subtract({hdr.udp.checksum});

		packet.extract(hdr.scion_common);
		packet.extract(hdr.scion_addr_common);

		meta.currHF = 0;

		transition select(hdr.scion_common.dl, hdr.scion_common.sl) {
			(0, 0): addr_dst_src_host_32_32;
			(0, 1): addr_dst_src_host_32_64;
			(0, 2): addr_dst_src_host_32_96;
			(0, 3): addr_dst_src_host_32_128;
			(1, 0): addr_dst_src_host_64_32;
			(1, 1): addr_dst_src_host_64_64;
			(1, 2): addr_dst_src_host_64_96;
			(1, 3): addr_dst_src_host_64_128;
			(2, 0): addr_dst_src_host_96_32;
			(2, 1): addr_dst_src_host_96_64;
			(2, 2): addr_dst_src_host_96_96;
			(2, 3): addr_dst_src_host_96_128;
			(3, 0): addr_dst_src_host_128_32;
			(3, 1): addr_dst_src_host_128_64;
			(3, 2): addr_dst_src_host_128_96;
			(3, 3): addr_dst_src_host_128_128;
		}
	}

	state addr_dst_src_host_32_32 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_src_host_32);

		transition path;
	}

	state addr_dst_src_host_32_64 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);

		transition path;
	}

	state addr_dst_src_host_32_96 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32_3);

		transition path;
	}

	state addr_dst_src_host_32_128 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_src_host_128);

		transition path;
	}

	state addr_dst_src_host_64_32 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32);

		transition path;
	}

	state addr_dst_src_host_64_64 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);

		transition path;
	}

	state addr_dst_src_host_64_96 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32_3);

		transition path;
	}

	state addr_dst_src_host_64_128 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_src_host_128);

		transition path;
	}

	state addr_dst_src_host_96_32 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_dst_host_32_3);
		packet.extract(hdr.scion_addr_src_host_32);

		transition path;
	}

	state addr_dst_src_host_96_64 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_dst_host_32_3);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);

		transition path;
	}

	state addr_dst_src_host_96_96 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_dst_host_32_3);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32_3);
	
		transition path;
	}

	state addr_dst_src_host_96_128 {
		packet.extract(hdr.scion_addr_dst_host_32);
		packet.extract(hdr.scion_addr_dst_host_32_2);
		packet.extract(hdr.scion_addr_dst_host_32_3);
		packet.extract(hdr.scion_addr_src_host_128);

		transition path;
	}

	state addr_dst_src_host_128_32 {
		packet.extract(hdr.scion_addr_dst_host_128);
		packet.extract(hdr.scion_addr_src_host_32);

		transition path;
	}

	state addr_dst_src_host_128_64 {
		packet.extract(hdr.scion_addr_dst_host_128);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);

		transition path;
	}

	state addr_dst_src_host_128_96 {
		packet.extract(hdr.scion_addr_dst_host_128);
		packet.extract(hdr.scion_addr_src_host_32);
		packet.extract(hdr.scion_addr_src_host_32_2);
		packet.extract(hdr.scion_addr_src_host_32_3);

		transition path;
	}

	state addr_dst_src_host_128_128 {
		packet.extract(hdr.scion_addr_dst_host_128);
		packet.extract(hdr.scion_addr_src_host_128);
		transition path;
	}

	state path {
		transition select(hdr.scion_common.pathType) {
		    PathType.EMPTY: accept;
			PathType.SCION: path_scion;
			PathType.ONEHOP: path_onehop;
			// Other path types are not supported
		}
	}

	state path_onehop {
		packet.extract(hdr.scion_info_field_0);
		udp_checksum.subtract({hdr.scion_info_field_0.segId});
		packet.extract(hdr.scion_hop_field_0);
		packet.extract(hdr.scion_hop_field_1);
		udp_checksum.subtract_all_and_deposit(meta.udp_checksum_tmp);
	
		transition accept;
	}

	state path_scion {
		packet.extract(hdr.scion_path_meta);
		udp_checksum.subtract({hdr.scion_path_meta.currInf, hdr.scion_path_meta.currHF, hdr.scion_path_meta.rsv, hdr.scion_path_meta.seg0Len, hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len});
		
		meta.currHF = hdr.scion_path_meta.currHF;

		// We assume there is at least one info field present
		transition select(hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len) {
			(0, 0): info_field_0;
			(_, 0): info_field_1;
			default: info_field_2;
		}		
	}

	state info_field_0 {
		packet.extract(hdr.scion_info_field_0);
		udp_checksum.subtract({hdr.scion_info_field_0.segId});

		hdr.scion_info_field_1.segId = 0;
		hdr.scion_info_field_2.segId = 0;

		transition jump_start;
	}

	state info_field_1 {
		packet.extract(hdr.scion_info_field_0);
		udp_checksum.subtract({hdr.scion_info_field_0.segId});

		packet.extract(hdr.scion_info_field_1);
		udp_checksum.subtract({hdr.scion_info_field_1.segId});

		hdr.scion_info_field_2.segId = 0;

		transition jump_start;
	}

	state info_field_2 {
		packet.extract(hdr.scion_info_field_0);
		udp_checksum.subtract({hdr.scion_info_field_0.segId});
		packet.extract(hdr.scion_info_field_1);
		udp_checksum.subtract({hdr.scion_info_field_1.segId});
		packet.extract(hdr.scion_info_field_2);
		udp_checksum.subtract({hdr.scion_info_field_2.segId});

		transition jump_start;
	}

	state jump_start {
		transition select(hdr.scion_path_meta.currHF) {
			0x00: current_hop_field;
			0x10 &&& 0x30: jump_16;
			0x08 &&& 0x38: jump_8;
			0x04 &&& 0x3C: jump_4;
			0x03 &&& 0x3F: jump_3;
			0x02 &&& 0x3F: jump_2;
			0x01 &&& 0x3F: jump_1;
		}
	}

	state jump_16 {
		packet.extract(hdr.scion_jump_16);

		transition select(hdr.scion_path_meta.currHF) {
			0x10 &&& 0x3F: current_hop_field;
			0x08 &&& 0x08: jump_8;
			0x04 &&& 0x0C: jump_4;
			0x03 &&& 0x0F: jump_3;
			0x02 &&& 0x0F: jump_2;
			0x01 &&& 0x0F: jump_1;
		}
	}

	state jump_8 {
		packet.extract(hdr.scion_jump_8);

		transition select(hdr.scion_path_meta.currHF) {
			0x08 &&& 0x0F: current_hop_field;
			0x04 &&& 0x04: jump_4;
			0x03 &&& 0x07: jump_3;
			0x02 &&& 0x07: jump_2;
			0x01 &&& 0x07: jump_1;
		}
	}

	state jump_4 {
		packet.extract(hdr.scion_jump_4);

		transition select(hdr.scion_path_meta.currHF) {
			0x04 &&& 0x07: current_hop_field;
			0x03 &&& 0x03: jump_3;
			0x02 &&& 0x03: jump_2;
			0x01 &&& 0x03: jump_1;
		}

	}	

	state jump_3 {
		packet.extract(hdr.scion_jump_3);
		packet.extract(hdr.scion_hop_field_0);
		udp_checksum.subtract_all_and_deposit(meta.udp_checksum_tmp);
	
		transition accept;
	}

	state jump_2 {
		packet.extract(hdr.scion_jump_2);
		packet.extract(hdr.scion_hop_field_0);
		udp_checksum.subtract_all_and_deposit(meta.udp_checksum_tmp);
	
		transition accept;
	}	
 
	state jump_1 {
		packet.extract(hdr.scion_jump_1);
		packet.extract(hdr.scion_hop_field_0);
		udp_checksum.subtract_all_and_deposit(meta.udp_checksum_tmp);
	
		transition accept;
	}

	state current_hop_field {
		packet.extract(hdr.scion_hop_field_0);
		udp_checksum.subtract_all_and_deposit(meta.udp_checksum_tmp);
	
		transition accept;
	}
}

parser ScionEgressParser(
		packet_in packet,
		out header_t hdr,
		out metadata_t meta,
		out egress_intrinsic_metadata_t eg_intr_md) {
	state start {
		packet.extract(eg_intr_md);
		transition accept;
	}
}

/*************************************************************************
**************  I N G R E S S	P R O C E S S I N G	*******************
*************************************************************************/


control ScionIngressControl(
		inout header_t hdr,
		inout metadata_t meta,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
	action send_to_cpu() {
		hdr.scion_cpu.setValid();
		hdr.scion_cpu.srcAddr = (bit<48>)ig_intr_md.ingress_port;
		hdr.scion_cpu.dstAddr = 0xffffffffffff;
		hdr.scion_cpu.etherType = 0x5C10;
		ig_tm_md.ucast_egress_port = PORT_CPU;
	}

	action drop() {
		// Mark to drop
		ig_dprsr_md.drop_ctl = 1;
	}

#ifndef DISABLE_IPV4
	action initialise_ipv4() {
		hdr.ipv4.setValid();
#ifndef DISABLE_IPV6
		hdr.ipv6.setInvalid();
#endif /* DISABLE_IPV6 */
		hdr.ethernet.etherType = EtherType.IPV4;

		hdr.ipv4.version = 4;
		hdr.ipv4.ihl = 5;
		hdr.ipv4.diffserv = 0;
		hdr.ipv4.totalLen = meta.payload_len + 20;
		hdr.ipv4.identification = 0;
		hdr.ipv4.flags = 0;
		hdr.ipv4.fragOffset = 0;
		hdr.ipv4.ttl = 64;
		hdr.ipv4.protocol = Proto.UDP;
		// Next fields are set in other functions
		//hdr.ipv4.hdrChecksum
		//hdr.ipv4.srcAddr
		//hdr.ipv4.dstAddr
	}
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
	action initialise_ipv6() {
		hdr.ipv6.setValid();
#ifndef DISABLE_IPV4
		hdr.ipv4.setInvalid();
#endif /* DISABLE_IPV4 */

		hdr.ethernet.etherType = EtherType.IPV6;

		hdr.ipv6.version = 6;
		hdr.ipv6.trafficClass = 0;
		hdr.ipv6.flowLabel = 0;
		hdr.ipv6.payloadLen = meta.payload_len;
		hdr.ipv6.nextHdr = Proto.UDP;
		hdr.ipv6.hopLimit = 64;
		// Next fields are set in other functions
		//hdr.ipv6.srcAddr
		//hdr.ipv6.dstAddr
	}
#endif /* DISABLE_IPV6 */

	// Verification of the MAC in the current hop field
	table tbl_mac_verification {
		key = {
			meta.segId: exact;
			meta.timestamp: exact;
			hdr.scion_hop_field_0.expTime: exact;
			hdr.scion_hop_field_0.inIf: exact;
			hdr.scion_hop_field_0.egIf: exact;
			hdr.scion_hop_field_0.mac: exact;
		}
#if defined DISABLE_IPV4 || defined DISABLE_IPV6
		size = 200000; // IPv4 or IPv6 only
#else
		size = 160000; // IPv4 and IPv6
#endif /* defined DISABLE_IPV4 || defined DISABLE_IPV6 */
		actions = {
			NoAction;
		}
		default_action = NoAction;
	}

	// Verify the port we received the packet on is the one we expected it on
	table tbl_ingress_verification {
		key = {
			meta.ingress: exact;
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			NoAction;
		}
		size = 64;
		default_action = NoAction;
	}

	// Check whether a packet is destined for the current ISD/AS
	table tbl_check_local {
		key = {
			hdr.scion_addr_common.dstISD: exact;
			hdr.scion_addr_common.dstAS: exact;
		}
		actions = {
			NoAction;
		}
		size = 1;
		default_action = NoAction;
	}

#ifndef DISABLE_IPV4
	action deliver_local_ipv4(PortId_t port, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv4();
		hdr.ipv4.dstAddr = hdr.scion_addr_dst_host_32.host;

		hdr.ethernet.dstAddr = dstMAC;
		hdr.udp.dstPort = dstPort;
	}

	action deliver_local_service_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv4();
		hdr.ipv4.dstAddr = dstIP;

		hdr.udp.dstPort = dstPort;
		hdr.ethernet.dstAddr = dstMAC;
	}
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
	action deliver_local_ipv6(PortId_t port, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv6();
		hdr.ipv6.dstAddr = hdr.scion_addr_dst_host_128.host;

		hdr.ethernet.dstAddr = dstMAC;
		hdr.udp.dstPort = dstPort;
	}

	action deliver_local_service_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv6();
		hdr.ipv6.dstAddr = dstIP;

		hdr.udp.dstPort = dstPort;
		hdr.ethernet.dstAddr = dstMAC;
	}
#endif /* DISABLE_IPV6 */

	// Determine egress port and destination address (IP and/or MAC) for local bound traffic
	table tbl_deliver_local {
		key = {
			hdr.scion_common.dl: exact;
			hdr.scion_common.dt: exact;
			hdr.scion_addr_dst_host_32.host: ternary;
			hdr.scion_addr_dst_host_128.host: ternary;
		}
		actions = {
#ifndef DISABLE_IPV4
			deliver_local_ipv4;
			deliver_local_service_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
			deliver_local_ipv6;
			deliver_local_service_ipv6;
#endif /* DISABLE_IPV6 */
			@defaultonly drop;
		}
		size = 16;
		default_action = drop();
	}

#ifndef DISABLE_IPV4
	action set_local_source_ipv4(bit<32> srcIp, bit<48> srcMAC, bit<16> srcPort) {
		hdr.ethernet.srcAddr = srcMAC;

		hdr.ipv4.srcAddr = srcIp;

		hdr.udp.srcPort = srcPort;
		hdr.udp.checksum = 0;
	}
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
	action set_local_source_ipv6(bit<128> srcIp, bit<48> srcMAC, bit<16> srcPort) {
		hdr.ethernet.srcAddr = srcMAC;

		hdr.ipv6.srcAddr = srcIp;

		hdr.udp.srcPort = srcPort;
		hdr.udp.checksum = 0;
		// Required checksum for IPv6 is computed in deparser
	}
#endif /* DISABLE_IPV6 */

	// Set the source IP/MAC address based on the egress port
	// We currently allow one IP and MAC per port, but it could be extended if we let it depend on the egress in the header as well. If we use ternary matching for this, it can be used only if desired
	table tbl_set_local_source {
		key = {
			ig_tm_md.ucast_egress_port: exact;
		}
		actions = {
#ifndef DISABLE_IPV4
			set_local_source_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
			set_local_source_ipv6;
#endif /* DISABLE_IPV6 */
			@defaultonly drop;
		}
		size = 64;
		default_action = drop();
	 }

#ifndef DISABLE_IPV4
	action forward_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv4();
		hdr.ipv4.dstAddr = dstIP;

		hdr.ethernet.dstAddr = dstMAC;
		hdr.udp.dstPort = dstPort;
	}

	action forward_remote_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		forward_ipv4(port, dstIP, dstMAC, dstPort);
	}

	action forward_local_ipv4(PortId_t port, bit<32> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		forward_ipv4(port, dstIP, dstMAC, dstPort);
	}
#endif /* DISABLE_IPV4 */

#ifndef DISABLE_IPV6
	action forward_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		ig_tm_md.ucast_egress_port = port;

		initialise_ipv6();
		hdr.ipv6.dstAddr = dstIP;

		hdr.ethernet.dstAddr = dstMAC;
		hdr.udp.dstPort = dstPort;
	}

	action forward_remote_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		forward_ipv6(port, dstIP, dstMAC, dstPort);
	}

	action forward_local_ipv6(PortId_t port, bit<128> dstIP, bit<48> dstMAC, bit<16> dstPort) {
		forward_ipv6(port, dstIP, dstMAC, dstPort);
	}
#endif /* DISABLE_IPV6 */

	// Determine where to forward packet to based on SCION egress interface 
	table tbl_forward {
		key = {
			meta.egress: exact;
		}
		actions = {
#ifndef DISABLE_IPV4
			forward_remote_ipv4;
			forward_local_ipv4;
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
			forward_remote_ipv6;
			forward_local_ipv6;
#endif /* DISABLE_IPV6 */
			@defaultonly drop;
		}
		size = 64;
		default_action = drop();
	}

	apply {
		// We are currently not using the egress pipeline
		ig_tm_md.bypass_egress = 1;

		// Check for parser errors as packets are not automatically dropped on errors
		if (ig_prsr_md.parser_err != PARSER_ERROR_OK) {
			drop();
			exit;
		}
		if (hdr.scion_common.pathType != PathType.EMPTY) {
		    meta.seg1Len = hdr.scion_path_meta.seg1Len;
        }
        
#ifndef DISABLE_IPV4
		if (hdr.ipv4.isValid()) {
			meta.payload_len = hdr.ipv4.totalLen - 20;
		}
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
		if (hdr.ipv6.isValid()) {
			meta.payload_len = hdr.ipv6.payloadLen;
		}
#endif /* DISABLE_IPV6 */

		bool local_destination = tbl_check_local.apply().hit;
		bool skip_processing = false;

		if(hdr.scion_common.pathType == PathType.SCION) {
			// Update metadata fields based on the currently selected info field
			if (hdr.scion_path_meta.currInf == 0) {
				meta.direction = hdr.scion_info_field_0.direction;
				meta.segId = hdr.scion_info_field_0.segId;
				meta.timestamp = hdr.scion_info_field_0.timestamp;
				meta.segLen = hdr.scion_path_meta.seg0Len;
				meta.nextINF = 1;
				meta.currHF2 = meta.currHF;
			} else if (hdr.scion_path_meta.seg1Len > 0 && hdr.scion_path_meta.currInf == 1) {
				meta.direction = hdr.scion_info_field_1.direction;
				meta.segId = hdr.scion_info_field_1.segId;
				meta.timestamp = hdr.scion_info_field_1.timestamp;
				meta.segLen = hdr.scion_path_meta.seg0Len + meta.seg1Len;
				meta.nextINF = 2;
				meta.currHF2 = meta.currHF;
			} else if (hdr.scion_path_meta.seg2Len > 0 && hdr.scion_path_meta.currInf == 2) {
				meta.direction = hdr.scion_info_field_2.direction;
				meta.segId = hdr.scion_info_field_2.segId;
				meta.timestamp = hdr.scion_info_field_2.timestamp;
				meta.segLen = 0; // Not relevant (and incorrect). This should make sure currInf is not updated
				meta.nextINF = 2;
				meta.currHF2 = meta.currHF;
			} else {
				// Drop and exit
				drop();
				exit;
			}

			// Compute the new segId value for the info field
			meta.nextSegId = meta.segId ^ hdr.scion_hop_field_0.mac[47:32];

			// Depending on the direction indicated in the info field, we need to use the next segId in the MAC computation and reverse the in- and egress interfaces
			if(meta.direction == 0) { // Only for up direction
				if(hdr.scion_hop_field_0.egIf == 0) {
					meta.nextSegId = meta.segId;
				} else {
					meta.segId = meta.nextSegId;
				}
				meta.ingress = hdr.scion_hop_field_0.egIf;
				meta.egress = hdr.scion_hop_field_0.inIf;
			} else {
				meta.ingress = hdr.scion_hop_field_0.inIf;
				meta.egress = hdr.scion_hop_field_0.egIf;
			}
		} else if(hdr.scion_common.pathType == PathType.ONEHOP) {
			if(local_destination) {
				if (ig_intr_md.ingress_port == PORT_CPU) {
					// Use second HF
					meta.egress = hdr.scion_hop_field_1.egIf;
					meta.ingress = hdr.scion_hop_field_1.inIf;
				} else {
					// If we receive a packet from another port than CPU we assume no MAC is set and we need to add this in the control plane, just as the ingress and egress
					send_to_cpu();
					skip_processing = true;
				} 
			} else {			
				// Use first HF
				meta.egress = hdr.scion_hop_field_0.egIf;
				meta.ingress = hdr.scion_hop_field_0.inIf;

				meta.segId = hdr.scion_info_field_0.segId;
				meta.timestamp = hdr.scion_info_field_0.timestamp;
				meta.nextSegId = hdr.scion_info_field_0.segId ^ hdr.scion_hop_field_0.mac[47:32];
			}
		} else if (hdr.scion_common.pathType == PathType.EMPTY) {
			if (ig_intr_md.ingress_port != PORT_CPU) {
				// If we receive a packet from another port than CPU we assume that the packet is addressed to this border router
				send_to_cpu();
				skip_processing = true;
			}
		} else {
			// Unsupported path type
			drop();
			exit;
		}

		bool mac_verification_successful = tbl_mac_verification.apply().hit;
		bool ingress_verification_successful = tbl_ingress_verification.apply().hit;
		meta.currHF2 = meta.currHF;

		// Check whether the MAC was correct and we received the packet on the expect ingress port, or whether verification should be skipped (in case of a one-hop path)
		if (((mac_verification_successful && ingress_verification_successful) || ig_intr_md.ingress_port == PORT_CPU) && !skip_processing) {
			// Check whether the packet is intended for the local ISD/AS
			if (local_destination) {
				if(hdr.scion_common.pathType == PathType.SCION && meta.direction == 0) {
					// Update the segId in the current info field
					if (hdr.scion_path_meta.currInf == 0) {
						hdr.scion_info_field_0.segId = meta.nextSegId;
					} else if (hdr.scion_path_meta.currInf == 1) {
						hdr.scion_info_field_1.segId = meta.nextSegId;
					} else if (hdr.scion_path_meta.currInf == 2) {
						hdr.scion_info_field_2.segId = meta.nextSegId;
					}
				}

				tbl_deliver_local.apply();
			} else {
				switch(tbl_forward.apply().action_run) {
#ifndef DISABLE_IPV4
					forward_local_ipv4:
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
					forward_local_ipv6: 
#endif /* DISABLE_IPV6 */
					{}
					default: {
						// Only update headers if the packet is forwarded to an external node
						// Update the segId in the current info field
						if (hdr.scion_path_meta.currInf == 0 || hdr.scion_common.pathType == PathType.ONEHOP) {
							hdr.scion_info_field_0.segId = meta.nextSegId;
						} else if (hdr.scion_path_meta.currInf == 1) {
							hdr.scion_info_field_1.segId = meta.nextSegId;
						} else if (hdr.scion_path_meta.currInf == 2) {
							hdr.scion_info_field_2.segId = meta.nextSegId;
						}
			
						if(hdr.scion_common.pathType == PathType.SCION) {
							// Increase the index to the current hop field and update the header
							@in_hash{ meta.currHF = meta.currHF + 1; }
							hdr.scion_path_meta.currHF = meta.currHF;
							// Assuming there is a next hop field...

							// Update currInf if needed
							@in_hash{ meta.currHF2 = meta.currHF2 + 1; }
							// Assuming currHF and currInf were valid

							if (meta.currHF2 == meta.segLen) { 
								// We assume the next segment is not empty (i.e. segLen > 0)
								hdr.scion_path_meta.currInf = meta.nextINF;
								// Recirculate to process next HF
								// TODO Upper bits might already be set now in which case this might refer to another pipeline
								ig_tm_md.ucast_egress_port[6:0] = 68;
								// Disable drop that might have been set by tbl_forward
								ig_dprsr_md.drop_ctl = 0;
							}
						}
					}
				}
			}

			// Set the source IP/MAC addresses and UDP source port based on the chosen egress port
			// When configuring make sure the destination and source IP type match, otherwise this will overwrite previous selection of IPv4/IPv6
			tbl_set_local_source.apply();
 		} else if(skip_processing) {
			// Packet will be forwarded to CPU
		}
	}
}

control ScionEgressControl(
		inout header_t hdr,
		inout metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


	apply {  
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control ScionIngressDeparser(
		packet_out packet,
		inout header_t hdr,
		in metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
	Checksum() ipv4_checksum;
	Checksum() udp_checksum;

	apply {
#ifndef DISABLE_IPV4
		if(hdr.ipv4.isValid()) {
			hdr.ipv4.hdrChecksum = ipv4_checksum.update(
				{hdr.ipv4.version,
				 hdr.ipv4.ihl,
				 hdr.ipv4.diffserv,
				 hdr.ipv4.totalLen,
				 hdr.ipv4.identification,
				 hdr.ipv4.flags,
				 hdr.ipv4.fragOffset,
				 hdr.ipv4.ttl,
				 hdr.ipv4.protocol,
				 hdr.ipv4.srcAddr,
				 hdr.ipv4.dstAddr});
		} 
#endif /* DISABLE_IPV4 */
#ifndef DISABLE_IPV6
		if(hdr.ipv6.isValid()) {
			// Update UDP checksum, as this also includes the data we need to take into account the fields we (possibly) changed in the SCION header
			if(hdr.scion_path_meta.isValid()) {
				hdr.udp.checksum = udp_checksum.update(data = {
										hdr.ipv6.srcAddr,
										hdr.ipv6.dstAddr,
										hdr.udp.srcPort,
										hdr.udp.dstPort,
										hdr.scion_path_meta.currInf, hdr.scion_path_meta.currHF, hdr.scion_path_meta.rsv, hdr.scion_path_meta.seg0Len, hdr.scion_path_meta.seg1Len, hdr.scion_path_meta.seg2Len,
										hdr.scion_info_field_0.segId,
										hdr.scion_info_field_1.segId,
										hdr.scion_info_field_2.segId,
										ig_md.udp_checksum_tmp
									}, zeros_as_ones = true);
		 	} else {
				// Assume it is a one-hop path
				hdr.udp.checksum = udp_checksum.update(data = {
										hdr.ipv6.srcAddr,
										hdr.ipv6.dstAddr,
										hdr.udp.srcPort,
										hdr.udp.dstPort,
										hdr.scion_info_field_0.segId,
										ig_md.udp_checksum_tmp
									}, zeros_as_ones = true);
			}
		}
#endif /* DISABLE_IPV6 */

		packet.emit<header_t>(hdr);
	}
}

control ScionEgressDeparser(
		packet_out packet,
		inout header_t hdr,
		in metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
	apply {
		packet.emit(hdr);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(ScionIngressParser(),
		 ScionIngressControl(),
		 ScionIngressDeparser(),
		 ScionEgressParser(),
		 ScionEgressControl(),
		 ScionEgressDeparser()) pipe;

Switch(pipe) main;
