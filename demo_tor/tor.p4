// Copyright (c) 2016, Google Inc.
//
// P4 specification for a ToR (top-of-rack) switch.
// Status: WORK IN PROGRESS
// Note: This code has not been tested and is expected to contain bugs.

//------------------------------------------------------------------------------
// Global defines
//------------------------------------------------------------------------------

#define CPU_PORT 64
#define NULL_PORT 256

#define ARP_REASON 1

#define ETHERTYPE_VLAN 0x8100, 0x9100, 0x9200, 0x9300
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_ND 0x6007
#define ETHERTYPE_LLDP 0x88CC

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define IP_PROTOCOLS_ICMP 1
#define IP_PROTOCOLS_ICMPv6 58

#define DEFAULT_VRF0 0

#define L2_VLAN 4050

#define VLAN_DEPTH 2

#define CPU_MIRROR_SESSION_ID 1024

#define PORT_COUNT 4

//------------------------------------------------------------------------------
// Protocol Header Definitions
//------------------------------------------------------------------------------

header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
  }
}

header_type ipv4_base_t {
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
    dstAddr : 32;
  }
}

// Fixed ipv6 header
header_type ipv6_base_t {
  fields {
    version : 4;
    traffic_class : 8;
    flowLabel : 20;
    payloadLength : 16;
    nextHeader : 8;
    hopLimit : 8;
    srcAddr : 128;
    dstAddr : 128;
  }
}

header_type udp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    hdr_length : 16;
    checksum : 16;
  }
}

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

// Same for both ip v4 and v6
header_type icmp_header_t {
  fields {
    icmpType: 8;
    code: 8;
    checksum: 16;
  }
}

header_type vlan_tag_t {
  fields {
    pcp : 3;
    cfi : 1;
    vid : 12;
    etherType : 16;
  }
}

header_type arp_t {
  fields {
    hwType : 16;
    protoType : 16;
    hwAddrLen : 8;
    protoAddrLen : 8;
    opcode : 16;
    hwSrcAddr : 48;
    protoSrcAddr : 32;
    hwDstAddr : 48;
    protoDstAddr : 32;
  }
}

//------------------------------------------------------------------------------
// Internal Header Definitions
//------------------------------------------------------------------------------

header_type cpu_header_t {
  fields {
    zeros : 64;
    reason : 16;
    port : 16;
  }
}

//------------------------------------------------------------------------------
// Metadata Header and Field List Definitions
//------------------------------------------------------------------------------

// Local meta-data for each packet being processed.
header_type local_metadata_t {
  fields {
    // VRF id assigned to the packet. Every packet should have a valid VRF id.
    vrf_id : 32;
    nexthop_index: 32;
    nexthop_group_id: 32;
    l4SrcPort: 16;
    l4DstPort: 16;
    class_id: 8;
    qid: 5;
    meter_index: 16;
    color: 2;
    icmp_code: 8;
    reason: 8;
    src_mac: 48;
  }
}

// Field List for packets destined to CPU.
field_list cpu_info {
  local_metadata.reason;
  standard_metadata.ingress_port;
}

//------------------------------------------------------------------------------
// Headers and Metadata Declarations
//------------------------------------------------------------------------------

header ethernet_t ethernet;
header ipv4_base_t ipv4_base;
header ipv6_base_t ipv6_base;
header icmp_header_t icmp_header;
header tcp_t tcp;
header udp_t udp;
header vlan_tag_t vlan_tag[VLAN_DEPTH];
header arp_t arp;

header cpu_header_t cpu_header;

metadata local_metadata_t local_metadata;

//------------------------------------------------------------------------------
// Parsers
//------------------------------------------------------------------------------

// Start with ethernet always.
parser start {
  return select(current(0, 64)) {
    0 :      parse_cpu_header;
    default: parse_ethernet;
  }
}

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    ETHERTYPE_VLAN: parse_vlan;
    ETHERTYPE_IPV4: parse_ipv4;
    ETHERTYPE_IPV6: parse_ipv6;
    ETHERTYPE_ARP:  parse_arp;
    default: ingress;
  }
}

parser parse_vlan {
  extract(vlan_tag[next]);
  return select(latest.etherType) {
    ETHERTYPE_VLAN : parse_vlan;
    ETHERTYPE_IPV4 : parse_ipv4;
    ETHERTYPE_IPV6 : parse_ipv6;
    default: ingress;
  }
}

parser parse_ipv4 {
  extract(ipv4_base);
  return select(latest.fragOffset, latest.protocol) {
    IP_PROTOCOLS_ICMP : parse_icmp;
    IP_PROTOCOLS_TCP  : parse_tcp;
    IP_PROTOCOLS_UDP  : parse_udp;
    default: ingress;
  }
}

parser parse_ipv6 {
  extract(ipv6_base);
  return select(ipv6_base.nextHeader) {
    IP_PROTOCOLS_ICMPv6: parse_icmp;
    IP_PROTOCOLS_TCP   : parse_tcp;
    IP_PROTOCOLS_UDP   : parse_udp;
    default: ingress;
  }
}

parser parse_tcp {
  extract(tcp);
  // Normalize TCP port metadata to common port metadata
  set_metadata(local_metadata.l4SrcPort, latest.srcPort);
  set_metadata(local_metadata.l4DstPort, latest.dstPort);
  return ingress;
}

parser parse_udp {
  extract(udp);
  // Normalize UDP port metadata to common port metadata
  set_metadata(local_metadata.l4SrcPort, latest.srcPort);
  set_metadata(local_metadata.l4DstPort, latest.dstPort);
  return ingress;
}

parser parse_icmp {
  extract(icmp_header);
  return ingress;
}

parser parse_arp {
  extract(arp);
  return ingress;
}

parser parse_cpu_header {
  extract(cpu_header);
  return parse_ethernet;
}

//------------------------------------------------------------------------------
// Global actions
//------------------------------------------------------------------------------

// Do nothing action.
action nop() {
}

// Drops the packet.
action drop_packet() {
  drop();
}

// Copy to the CPU
action copy_packet_to_cpu() {
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, cpu_info);
}

// Send to the CPU
action send_packet_to_cpu() {
  modify_field(standard_metadata.egress_spec, CPU_PORT);
}

//------------------------------------------------------------------------------
// Tables and Control Flows
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Switch & Port Properties
//------------------------------------------------------------------------------

//-----------------------------------
// Switch Properties
//-----------------------------------

action set_smac(smac) {
  modify_field(local_metadata.src_mac, smac);
}

table switch_properties {
  actions {
    set_smac;
  }
}

//-----------------------------------
// Port Properties
//-----------------------------------

// Sets the ’special' L2 Vlan that we allow (every other L2 packet forwarding is
// disabled).
action set_l2_vlan(vid) {
  modify_field(vlan_tag[0].vid, vid);
  modify_field(vlan_tag[0].etherType, 0x8100);
}

table port_properties {
  reads {
    standard_metadata.ingress_port: exact;
  }
  actions {
    set_l2_vlan;
  }
  default_action: set_l2_vlan(L2_VLAN);
}

//------------------------------------------------------------------------------
// Packet Classification
//------------------------------------------------------------------------------

//-----------------------------------
// Map traffic to a particular class
//-----------------------------------

action set_class_id(class_id) {
  modify_field(local_metadata.class_id, class_id);
}

table class_id_assignment {
  reads {
    ethernet.etherType: exact;

    ipv4_base.ttl: ternary;
    ipv6_base.hopLimit: ternary;
    ipv4_base.dstAddr: ternary;
    ipv6_base.dstAddr mask 0xFFFFFFFFFFFFFFFF: ternary;
    ipv4_base.protocol: exact;
    ipv6_base.nextHeader: exact;

    local_metadata.l4SrcPort: exact;
    local_metadata.l4DstPort: exact;

    vlan_tag[0].vid: exact;
    vlan_tag[0].pcp: exact;
  }
  actions {
    set_class_id;
  }
  default_action: set_class_id(0);
}

//-----------------------------------
// Map traffic to a particular VRF
//-----------------------------------

// Sets the vrf id on the local metadata.
action set_vrf(vrf_id) {
  modify_field(local_metadata.vrf_id, vrf_id);
}

table vrf_classifier_table {
  reads {
    ethernet.etherType : exact;
    ethernet.srcAddr : exact;
    ethernet.dstAddr : exact;
    standard_metadata.ingress_port: exact;
  }
  actions {
    // Sets the VRF on a table hit.
    set_vrf;
  }
  default_action: set_vrf(DEFAULT_VRF0);
}

// Controls Packet Classification including IP Spoofing
control ingress_pkt_classifier {
  apply(class_id_assignment);
  apply(vrf_classifier_table);
}

//------------------------------------------------------------------------------
// L3 Routing (My MAC check)
//------------------------------------------------------------------------------

// Drops packets that do not need to be part of L3 forwarding.
// Equivalent of BCM MY_STATION table ?
table l3_routing_classifier {
  reads {
    ethernet.dstAddr : exact;
  }
  actions {
    nop;
    drop_packet;
  }
  default_action: drop_packet();
}

//------------------------------------------------------------------------------
// IPv4 and IPv6 L3 Forwarding
//------------------------------------------------------------------------------

action l3_set_ecmp_group(nexthop_group_id) {
  modify_field(local_metadata.nexthop_group_id, nexthop_group_id);
}

action l3_egress_port_set(port) {
  modify_field(standard_metadata.egress_spec, port);
}

action l3_forwarding(nexthop_index) {
  modify_field(local_metadata.nexthop_index, nexthop_index);
}
//-----------------------------------
// IPv4 L3 Forwarding
//-----------------------------------

// Perform override L3 forwarding based destination addr.
table l3_ipv4_override_table {
  reads {
    ipv4_base.dstAddr : lpm;
  }
  actions {
    l3_forwarding;
//    l3_set_ecmp_group;
  }
}

table l3_ipv4_vrf_table {
  reads {
    local_metadata.vrf_id: exact;
    ipv4_base.dstAddr : lpm;
  }
  actions {
    l3_forwarding;
//    l3_set_ecmp_group;
  }
}

table l3_ipv4_fallback_table {
  reads {
    ipv4_base.dstAddr : lpm;
  }
  actions {
    l3_forwarding;
//    l3_set_ecmp_group;
  }
}

table l3_ipv4_nexthop_resolve {
  reads {
    local_metadata.nexthop_index : exact;
  }
  actions {
    l3_egress_port_set;
  }
  default_action: l3_egress_port_set(NULL_PORT);
}


// LPM forwarding for IPV4 packets.
control ingress_ipv4_l3_forwarding {
  apply(l3_ipv4_override_table) {
    miss {
      apply(l3_ipv4_vrf_table) {
        miss {
          apply(l3_ipv4_fallback_table);
        }
      }
    }
  }
  apply(l3_ipv4_nexthop_resolve);
}

//-----------------------------------
// IPv6 L3 Forwarding
//-----------------------------------

// Perform override L3 forwarding based destination addr.
table l3_ipv6_override_table {
  reads {
    ipv6_base.dstAddr : lpm;
  }
  actions {
    // L3 forwarding on a match.
    l3_forwarding;
  }
}

table l3_ipv6_vrf_table {
  reads {
    local_metadata.vrf_id: exact;
    ipv6_base.dstAddr : lpm;
  }
  actions {
    l3_forwarding;
  }
}

table l3_ipv6_fallback_table {
  reads {
    ipv6_base.dstAddr : lpm;
  }
  actions {
    l3_forwarding;
  }
}

table l3_ipv6_nexthop_resolve {
  reads {
    local_metadata.nexthop_index : exact;
  }
  actions {
    l3_egress_port_set;
  }
  default_action: l3_egress_port_set(NULL_PORT);
}

// LPM forwarding for IPV6 packets.
control ingress_ipv6_l3_forwarding {
  apply(l3_ipv6_override_table) {
    miss {
      apply(l3_ipv6_vrf_table) {
        miss {
          apply(l3_ipv6_fallback_table);
        }
      }
    }
  }
  apply(l3_ipv6_nexthop_resolve);
}

//-----------------------------------
// IPv4/v6 L3 Forwarding
//-----------------------------------

// Controls LPM forwarding.
control ingress_lpm_forwarding {
  if (valid(ipv4_base)) {
    ingress_ipv4_l3_forwarding();
  } else {
    if (valid(ipv6_base)) {
      ingress_ipv6_l3_forwarding();
    }
  }
}

//------------------------------------------------------------------------------
// Egress Rewrite
//------------------------------------------------------------------------------

action rewrite_mac(smac) {
  modify_field(ethernet.srcAddr, smac);
}

table egress_port_smac {
  reads {
    standard_metadata.egress_port: exact;
  }
  actions {
    rewrite_mac;
    drop_packet;
  }
  default_action: drop_packet();
}

// Sets the egress mac.
action egress_ipv4_ipv6_update_mac(dst_mac) {
  modify_field(ethernet.dstAddr, dst_mac);
  // if switch_properties is used
//  modify_field(ethernet.srcAddr, local_metadata.src_mac);
}

table egress_nexthop_table {
  reads {
    local_metadata.nexthop_index : exact;
  }
  actions {
    egress_ipv4_ipv6_update_mac;
  }
}


//------------------------------------------------------------------------------
// Send/Copy to the CPU
//------------------------------------------------------------------------------

// send to cpu action (aka redirect to cpu)
action send_to_cpu(reason) {
  add_header(cpu_header);
  modify_field(cpu_header.reason, reason);
  modify_field(cpu_header.port, standard_metadata.ingress_port);
  send_packet_to_cpu();
}

// copy to cpu action
action copy_to_cpu(reason) {
  modify_field(local_metadata.reason, reason);
  copy_packet_to_cpu();
}

//-----------------------------------
// Send/Copy to CPU in a given queue
//-----------------------------------

action set_queue_and_copy_to_cpu(qid, reason) {
  modify_field(local_metadata.qid, qid);
  copy_to_cpu(reason);
}

action set_queue_and_send_to_cpu(qid, reason) {
  modify_field(local_metadata.qid, qid);
  send_to_cpu(reason);
}

table cpu_queue_assignment {
  reads {
    standard_metadata.ingress_port: exact;
    standard_metadata.egress_spec: exact;

    ethernet.etherType: exact;

    ipv4_base.diffserv: exact;
    ipv6_base.traffic_class: exact;
    ipv4_base.ttl: ternary;
    ipv6_base.hopLimit: ternary;
    ipv4_base.srcAddr: ternary;
    ipv4_base.dstAddr: ternary;
    ipv4_base.protocol: exact;
    ipv6_base.nextHeader: exact;

    local_metadata.icmp_code: exact;

    vlan_tag[0].vid: exact;
    vlan_tag[0].pcp: exact;

    local_metadata.class_id: exact;
    local_metadata.vrf_id: exact;
  }
  actions {
    set_queue_and_copy_to_cpu;
    set_queue_and_send_to_cpu;
  }
  default_action: set_queue_and_send_to_cpu(0, 0);
}

// TODO - This should be a runtime entry in the above table
table send_arp_to_cpu {
  actions {
    send_to_cpu;
  }
  default_action: send_to_cpu(ARP_REASON);
}

//------------------------------------------------------------------------------
// Receive from CPU 
//------------------------------------------------------------------------------

action set_egress_port_and_decap_cpu_header() {
  modify_field(standard_metadata.egress_spec, cpu_header.port);
  remove_header(cpu_header);
}

table process_cpu_header {
  actions {
    set_egress_port_and_decap_cpu_header;
  }
  default_action: set_egress_port_and_decap_cpu_header();
}

//------------------------------------------------------------------------------
// Meters
//------------------------------------------------------------------------------

//-----------------------------------
// Meter Table
//-----------------------------------

meter meter_table {
  type : bytes;
  instance_count : PORT_COUNT;
}

//-----------------------------------
// Meter Assignment
//-----------------------------------

action set_meter_index(meter_index) {
  modify_field(local_metadata.meter_index, meter_index);
  execute_meter(meter_table, meter_index, local_metadata.color);
}

table meter_assignment_and_evaluate {
  reads {
    standard_metadata.ingress_port: exact;
    standard_metadata.egress_spec: exact;
    ethernet.etherType: exact;
    ipv4_base.dstAddr: ternary;
    local_metadata.class_id: exact;
  }
  actions {
    set_meter_index;
    nop;
  }
//  default_action: nop();
}

//-----------------------------------
// Meter Stats
//-----------------------------------

counter meter_stats {
  type : packets;
  direct : meter_action;
}

//-----------------------------------
// Meter Action -
//  Run action based on meter color
//-----------------------------------

action meter_deny() {
  drop();
}

action meter_permit() {
}

table meter_action {
  reads {
    local_metadata.color : exact;
    local_metadata.meter_index : exact;
  }

  actions {
    meter_permit;
    meter_deny;
  }
}

//-----------------------------------
// Meter Control Flow
//-----------------------------------

// Meter control flow
control process_ingress_meters {
  apply(meter_assignment_and_evaluate) {
    hit {
      apply(meter_action);
    }
  }
}

//------------------------------------------------------------------------------
// Main Ingress Control
//------------------------------------------------------------------------------

// Performs ingress control.
control ingress {
//  apply(switch_properties);
//  apply(port_properties);
  if (valid(cpu_header)) {
      apply(process_cpu_header);
  } else {
    // TODO - ARP processing should not be special cased
    if (valid(arp)) {
       apply(send_arp_to_cpu);
    } else {
      ingress_pkt_classifier();
      apply(l3_routing_classifier);
      ingress_lpm_forwarding();
      apply(cpu_queue_assignment);
      process_ingress_meters();
    }
  }
}

//------------------------------------------------------------------------------
// Main Egress Control
//------------------------------------------------------------------------------

// Performs egress control.
control egress {
  if (not valid(cpu_header)) {
    apply(egress_port_smac);
    if(valid(ipv4_base) or valid(ipv6_base)) {
      apply(egress_nexthop_table);
    }
  }
}

