/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "tor_mgr.h"

#include <arpa/inet.h>

// #include <functional>
#include <boost/bind.hpp>

#include <future>
#include <limits>

#include "google/rpc/code.pb.h"

using grpc::ClientContext;
using grpc::Status;
using grpc::ClientReaderWriter;

#define CPU_PORT static_cast<uint16_t>(64)
#define ARP_REASON static_cast<uint16_t>(1)

namespace {

enum CPU_REASON {
  NO_ARP_ENTRY = 0,
  ARP_MSG = 1,
  DATA_PKT = 2,
};

size_t set_cpu_header(cpu_header_t *cpu_header, uint16_t reason,
                      uint16_t port) {
  memset(cpu_header->zeros, 0, sizeof(cpu_header->zeros));
  cpu_header->reason = htons(reason);
  cpu_header->port = htons(port);
  return sizeof(*cpu_header);
}

size_t set_eth_header(eth_header_t *eth_header,
                      const unsigned char (&dst_addr)[6],
                      const unsigned char (&src_addr)[6],
                      uint16_t ethertype) {
  memcpy(eth_header->dst_addr, dst_addr, sizeof(dst_addr));
  memcpy(eth_header->src_addr, src_addr, sizeof(src_addr));
  eth_header->ethertype = htons(ethertype);
  return sizeof(*eth_header);
}

size_t set_arp_header(arp_header_t *arp_rep, uint16_t opcode,
                      const unsigned char (&hw_src_addr)[6],
                      uint32_t proto_src_addr,
                      const unsigned char (&hw_dst_addr)[6],
                      uint32_t proto_dst_addr) {
  arp_rep->hw_type = 1;
  arp_rep->hw_type = htons(arp_rep->hw_type);
  arp_rep->proto_type = 0x800;
  arp_rep->proto_type = htons(arp_rep->proto_type);
  arp_rep->hw_addr_len = sizeof(hw_src_addr);
  arp_rep->proto_addr_len = sizeof(proto_src_addr);
  arp_rep->opcode = htons(opcode);
  memcpy(arp_rep->hw_src_addr, hw_src_addr, sizeof(hw_src_addr));
  arp_rep->proto_src_addr = htonl(proto_src_addr);
  memcpy(arp_rep->hw_dst_addr, hw_dst_addr, sizeof(hw_dst_addr));
  arp_rep->proto_dst_addr = htonl(proto_dst_addr);
  return sizeof(*arp_rep);
}

}  // namespace

struct MgrHandler {
  MgrHandler(TorMgr *mgr)
      : tor_mgr(mgr) { }

  TorMgr *tor_mgr;
};

struct PacketHandler : public MgrHandler {
  PacketHandler(TorMgr *mgr, TorMgr::Packet &&pkt_copy)
      : MgrHandler(mgr), pkt_copy(std::move(pkt_copy)) { }

  void operator()() {
    char *pkt = pkt_copy.data();
    size_t size = pkt_copy.size();
    size_t offset = 0;
    cpu_header_t cpu_hdr;
    if ((size - offset) < sizeof(cpu_hdr)) return;
    char zeros[8];
    memset(zeros, 0, sizeof(zeros));
    if (memcmp(zeros, pkt, sizeof(zeros))) return;
    memcpy(&cpu_hdr, pkt, sizeof(cpu_hdr));
    cpu_hdr.reason = ntohs(cpu_hdr.reason);
    cpu_hdr.port = ntohs(cpu_hdr.port);
    offset += sizeof(cpu_hdr);
    if ((size - offset) < sizeof(eth_header_t)) return;
    offset += sizeof(eth_header_t);
    if (cpu_hdr.reason == NO_ARP_ENTRY) {
      if ((size - offset) < sizeof(ipv4_header_t)) return;
      ipv4_header_t ip_hdr;
      memcpy(&ip_hdr, pkt + offset, sizeof(ip_hdr));
      ip_hdr.dst_addr = ntohl(ip_hdr.dst_addr);
      tor_mgr->handle_ip(std::move(pkt_copy), ip_hdr.dst_addr);
    } else if (cpu_hdr.reason == ARP_MSG) {
      if ((size - offset) < sizeof(arp_header_t)) return;
      arp_header_t arp_header;
      memcpy(&arp_header, pkt + offset, sizeof(arp_header));
      arp_header.hw_type = ntohs(arp_header.hw_type);
      arp_header.proto_type = ntohs(arp_header.proto_type);
      arp_header.opcode = ntohs(arp_header.opcode);
      arp_header.proto_src_addr = ntohl(arp_header.proto_src_addr);
      arp_header.proto_dst_addr = ntohl(arp_header.proto_dst_addr);
      tor_mgr->handle_arp(arp_header);
    }
  }

  TorMgr::Packet pkt_copy;
};

struct CounterQueryHandler : public MgrHandler {
  CounterQueryHandler(TorMgr *mgr,
                      const std::string &counter_name,
                      size_t index,
                      std::promise<p4::CounterData> &promise)
      : MgrHandler(mgr), counter_name(counter_name), index(index),
        promise(promise) { }

  void operator()() {
    p4::CounterData d;
    int rc = tor_mgr->query_counter_(counter_name, index, &d);
    if (rc) {
      d.set_packet_count(
          std::numeric_limits<decltype(d.packet_count())>::max());
    }
     promise.set_value(d);
  }

  std::string counter_name;
  size_t index;
  std::promise<p4::CounterData> &promise;
};

struct ConfigUpdateHandler : public MgrHandler {
  ConfigUpdateHandler(TorMgr *mgr,
                      const std::string &config_buffer,
                      std::promise<int> &promise)
      : MgrHandler(mgr), config_buffer(config_buffer), promise(promise) { }

  void operator()() {
    int rc = tor_mgr->update_config_(config_buffer);
    promise.set_value(rc);
  }

  const std::string &config_buffer;
  std::promise<int> &promise;
};

class PacketIOSyncClient {
 public:
  PacketIOSyncClient(TorMgr *tor_mgr,
                     std::shared_ptr<Channel> channel)
      : tor_mgr(tor_mgr), stub_(p4::PI::NewStub(channel)) {
    stream = stub_->PacketIO(&context);
  }

  void recv_packet_in() {
    recv_thread = std::thread([this]() {
        p4::PacketInUpdate packet_in;
        while (stream->Read(&packet_in)) {
          std::cout << "Received packet in bro!\n";
          const auto &packet = packet_in.packet();
          TorMgr::Packet pkt_copy(packet.payload().begin(),
                                           packet.payload().end());
          tor_mgr->post_event(
              PacketHandler(tor_mgr, std::move(pkt_copy)));
        }
    });
  }

  void send_init(int device_id) {
    std::cout << "Sending init\n";
    p4::PacketOutUpdate packet_out_init;
    packet_out_init.mutable_init()->set_device_id(device_id);
    stream->Write(packet_out_init);
  }

  void send_packet_out(std::string bytes) {
    std::cout << "Sending packet out\n";
    p4::PacketOutUpdate packet_out;
    packet_out.mutable_packet()->set_payload(std::move(bytes));
    stream->Write(packet_out);
  }

 private:
  TorMgr *tor_mgr{nullptr};
  std::unique_ptr<p4::PI::Stub> stub_;
  std::thread recv_thread;
  ClientContext context;
  std::unique_ptr<ClientReaderWriter<p4::PacketOutUpdate, p4::PacketInUpdate> >
  stream;
};

TorMgr::TorMgr(int dev_id, pi_p4info_t *p4info,
                                 boost::asio::io_service &io_service,
                                 std::shared_ptr<Channel> channel)
    : dev_id(dev_id), p4info(p4info), io_service(io_service),
      device_stub_(p4::tmp::Device::NewStub(channel)),
      pi_stub_(p4::PI::NewStub(channel)),
      packet_io_client(new PacketIOSyncClient(this, channel)) {
}

TorMgr::~TorMgr() {
}

int
TorMgr::assign() {
  if (assigned) return 0;
  p4::tmp::DeviceAssignRequest request;
  request.set_device_id(dev_id);
  char *p4info_json = pi_serialize_config(p4info, 0);
//  request.set_native_p4info_json(p4info_json);
  free(p4info_json);
  auto extras = request.mutable_extras();
  auto kv = extras->mutable_kv();
  (*kv)["port"] = "9090";
  (*kv)["notifications"] = "ipc:///tmp/bmv2-0-notifications.ipc";
  (*kv)["cpu_iface"] = "veth251";

  ::google::rpc::Status rep;
  ClientContext context;
  Status status = device_stub_->DeviceAssign(&context, request, &rep);
  assert(status.ok());

  packet_io_client->send_init(dev_id);
  packet_io_client->recv_packet_in();

  return rep.code();
}

namespace {

template <typename T> std::string uint_to_string(T i);

template <>
std::string uint_to_string<uint8_t>(uint8_t i) {
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

template <>
std::string uint_to_string<uint16_t>(uint16_t i) {
  i = ntohs(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

template <>
std::string uint_to_string<uint32_t>(uint32_t i) {
  i = ntohl(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

}  // namespace

int
TorMgr::add_one_entry(p4::TableEntry *match_action_entry) {
  p4::TableWriteRequest request;
  request.set_device_id(dev_id);
  auto update = request.add_updates();
  update->set_type(p4::TableUpdate_Type_INSERT);
  update->set_allocated_table_entry(match_action_entry);

  p4::TableWriteResponse rep;
  ClientContext context;
  Status status = pi_stub_->TableWrite(&context, request, &rep);
  assert(status.ok());

  update->release_table_entry();

  return rep.errors().size();
}

void TorMgr::set_ignore_mask_(p4::TableEntry &entry, std::vector <std::pair<const char *, int>> & fields) {
  for(const auto &f : fields) {
    auto mf = entry.add_match();
    mf->set_field_id(pi_p4info_field_id_from_name(p4info, f.first));
    auto mf_ternary = mf->mutable_ternary();
    mf_ternary->set_value(std::string(f.second, 0));
    mf_ternary->set_mask(std::string(f.second, 0));
  }
}

int TorMgr::set_arp_punt_(void) {
  int rc = 0;
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "punt_table");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_queue_and_send_to_cpu");

  p4::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_field_id_from_name(p4info, "ethernet.etherType"));
  auto mf_ternary = mf->mutable_ternary();
  mf_ternary->set_value(uint_to_string(static_cast<uint16_t>(0x0806)));
  mf_ternary->set_mask(uint_to_string(static_cast<uint16_t>(0xFFFF)));
  static std::vector<std::pair<const char *, int>> fields= {
  {"standard_metadata.ingress_port", 2},
  {"standard_metadata.egress_spec", 2}, 
  {"ipv4_base.diffserv", 1},
  {"ipv6_base.traffic_class", 1},
  {"ipv4_base.ttl", 1},
  {"ipv6_base.hopLimit", 1},
  {"ipv4_base.srcAddr", 4},
  {"ipv4_base.dstAddr", 4},
  {"ipv6_base.srcAddr", 16},
  {"ipv6_base.dstAddr", 16},
  {"ipv4_base.protocol", 1},
  {"ipv6_base.nextHeader", 1},
  {"arp.protoDstAddr", 4},
  {"local_metadata.icmp_code", 8},
  {"vlan_tag[0].vid", 1},
  {"vlan_tag[0].pcp", 1},
  {"local_metadata.class_id", 1},
  {"local_metadata.vrf_id" , 4}
	};
  set_ignore_mask_(match_action_entry, fields);

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "qid"));
    param->set_value(uint_to_string((uint8_t)0));
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "reason"));
    param->set_value(uint_to_string(ARP_REASON));
  }

  rc = add_one_entry(&match_action_entry);
  return rc;
}

int TorMgr::set_nexthop_egress_port(uint32_t nhopindex, uint16_t port) {
  int rc = 0;
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "l3_nexthop_resolve");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "l3_egress_port_set");

  p4::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_field_id_from_name(p4info, "local_metadata.nexthop_index"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(nhopindex));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "port"));
    param->set_value(uint_to_string(port));
  }

  rc = add_one_entry(&match_action_entry);
  return rc;
}

int
TorMgr::add_route_(uint32_t prefix, int pLen, uint32_t nhopindex,
			    uint16_t port,
                            UpdateMode update_mode) {
  int rc = 0;
  if (update_mode == UpdateMode::DEVICE_STATE) {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "l3_ipv4_vrf_table");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "l3_forwarding");

    p4::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);

    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_field_id_from_name(p4info, "local_metadata.vrf_id"));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(uint_to_string(0U));
    mf->set_field_id(pi_p4info_field_id_from_name(p4info, "ipv4_base.dstAddr"));
    auto mf_lpm = mf->mutable_lpm();
    mf_lpm->set_value(uint_to_string(prefix));
    mf_lpm->set_prefix_len(pLen);

    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "nexthop_index"));
      param->set_value(uint_to_string(nhopindex));
    }

    rc = add_one_entry(&match_action_entry);


    // add the nexthop resolve table
    rc = set_nexthop_egress_port(nhopindex, port);
  }

  if (update_mode == UpdateMode::CONTROLLER_STATE) {
    next_hops[nhopindex] = port;
  }

  return rc;
}

int
TorMgr::add_route(uint32_t prefix, int pLen,
	                       uint32_t nhop,
			       uint16_t port) {
  int rc = 0;
  rc |= add_route_(prefix, pLen, nhop, port, UpdateMode::CONTROLLER_STATE);
  rc |= add_route_(prefix, pLen, nhop, port, UpdateMode::DEVICE_STATE);
  return rc;
}

int
TorMgr::add_arp_entry(uint32_t addr,
                               const unsigned char (&mac_addr)[6]) {
  // check if ARP Entry is already installed/changed
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ingress_nexthop_table");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "ipv4_ipv6_update_mac");

  p4::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_field_id_from_name(
      p4info, "local_metadata.nexthop_index"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(addr));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "dst_mac"));
    param->set_value(std::string(reinterpret_cast<const char *>(mac_addr),
                                 sizeof(mac_addr)));
  }

  return add_one_entry(&match_action_entry);
}

int
TorMgr::assign_mac_addr(uint16_t port,
                                 const unsigned char (&mac_addr)[6]) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "egress_port_smac");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "rewrite_mac");

  p4::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);

  auto mf = match_action_entry.add_match();
  mf->set_field_id(pi_p4info_field_id_from_name(
      p4info, "standard_metadata.egress_port"));
  auto mf_exact = mf->mutable_exact();
  mf_exact->set_value(uint_to_string(port));

  auto entry = match_action_entry.mutable_action();
  auto action = entry->mutable_action();
  action->set_action_id(a_id);
  {
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "smac"));
    param->set_value(std::string(reinterpret_cast<const char *>(mac_addr),
                                 sizeof(mac_addr)));
  }

  return add_one_entry(&match_action_entry);
}

int
TorMgr::set_one_default_entry(pi_p4_id_t t_id,
                                       p4::Action *action) {
  p4::TableEntry match_action_entry;
  match_action_entry.set_table_id(t_id);
  auto entry = match_action_entry.mutable_action();
  entry->set_allocated_action(action);
  auto rc = add_one_entry(&match_action_entry);
  entry->release_action();
  return rc;
}

int
TorMgr::set_default_entries() {
  int rc = 0;

#if 0
  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "_drop");
    p4::TableEntry match_action_entry;
    match_action_entry.set_table_id(t_id);

    auto mf = match_action_entry.add_match();
    mf->set_field_id(pi_p4info_field_id_from_name(
        p4info, "routing_metadata.nhop_ipv4"));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(uint_to_string(static_cast<uint32_t>(0)));

    auto entry = match_action_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);

    if (add_one_entry(&match_action_entry))
      std::cout << "Error when adding entry to 'forward'\n";
  }
#endif
  rc = set_arp_punt_();
  return rc;
}

int
TorMgr::static_config_(UpdateMode update_mode) {
  add_route_(0x0a00000a, 32, 0x0a00000a, 1, update_mode);
  add_route_(0x0a00010a, 32, 0x0a00010a, 2, update_mode);
  {
    unsigned char hw1[6] = {0x00, 0xaa, 0xbb, 0x00, 0x00, 0x00};
    unsigned char hw2[6] = {0x00, 0xaa, 0xbb, 0x00, 0x00, 0x01};
    add_iface_(1, 0x0a000001, hw1, update_mode);
    add_iface_(2, 0x0a000101, hw2, update_mode);
  }
  return 0;
}

int
TorMgr::static_config() {
  int rc = 0;
  rc |= static_config_(UpdateMode::CONTROLLER_STATE);
  rc |= static_config_(UpdateMode::DEVICE_STATE);
  return rc;
}

void
TorMgr::send_packetout(const char *data, size_t size) {
  packet_io_client->send_packet_out(std::string(data, size));
}

void
TorMgr::handle_arp_request(const arp_header_t &arp_header) {
  for (const auto &iface : ifaces) {
    if (iface.ip_addr == arp_header.proto_dst_addr) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, iface.port_num);

      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          rep.get() + offset);
      offset += set_eth_header(eth_header, arp_header.hw_src_addr,
                               iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(
          rep.get() + offset);
      set_arp_header(arp_rep, 2, iface.mac_addr, iface.ip_addr,
                     arp_header.hw_src_addr, arp_header.proto_src_addr);

      std::cout << "Sending ARP reply  on " << iface.port_num << "\n";
      send_packetout(rep.get(), rep_size);
      return;
    }
  }
}

void
TorMgr::handle_arp_reply(const arp_header_t &arp_header) {
  uint32_t dst_addr = arp_header.proto_src_addr;
  add_arp_entry(dst_addr, arp_header.hw_src_addr);
  auto it = packet_queues.find(dst_addr);
  if (it != packet_queues.end()) {
    for (auto &p : it->second) {
      size_t offset = 0;
      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(p.data());
      offset += set_cpu_header(cpu_header, DATA_PKT, next_hops[dst_addr]);
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          p.data() + offset);
      memcpy(eth_header->dst_addr, arp_header.hw_src_addr,
             sizeof(eth_header->dst_addr));
      std::cout << "Reinjecting data packet\n";
      send_packetout(p.data(), p.size());
    }
    packet_queues.erase(it);
  }
}

void
TorMgr::handle_arp(const arp_header_t &arp_header) {
  switch (arp_header.opcode) {
    case 1:  // request
      std::cout << "Arp request\n";
      handle_arp_request(arp_header);
      break;
    case 2:  // reply
      std::cout << "Arp rep\n";
      handle_arp_reply(arp_header);
      break;
    default:
      assert(0);
  }
}

void
TorMgr::send_arp_request(uint16_t port, uint32_t dst_addr) {
  for (const auto &iface : ifaces) {
    if (iface.port_num == port) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, port);

      unsigned char broadcast_addr[6];
      memset(broadcast_addr, 0xff, sizeof(broadcast_addr));
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          rep.get() + offset);
      offset += set_eth_header(eth_header, broadcast_addr,
                               iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(
          rep.get() + offset);
      set_arp_header(arp_rep, 1, iface.mac_addr, iface.ip_addr,
                     broadcast_addr, dst_addr);

      std::cout << "Sending ARP request\n";
      send_packetout(rep.get(), rep_size);
      return;
    }
  }
}

void
TorMgr::handle_ip(Packet &&pkt_copy, uint32_t dst_addr) {
  auto it = next_hops.find(dst_addr);
  if (it == next_hops.end()) return;
  // creates a queue if does not exist
  PacketQueue &queue = packet_queues[dst_addr];
  queue.push_back(std::move(pkt_copy));
  send_arp_request(it->second, dst_addr);
}

void
TorMgr::add_iface_(uint16_t port_num, uint32_t ip_addr,
                            const unsigned char (&mac_addr)[6],
                            UpdateMode update_mode) {
  if (update_mode == UpdateMode::CONTROLLER_STATE)
    ifaces.push_back(Iface::make(port_num, ip_addr, mac_addr));
  if (update_mode == UpdateMode::DEVICE_STATE) {
    for (const auto &iface : ifaces) {
      if (iface.port_num == port_num) {
        assign_mac_addr(port_num, iface.mac_addr);
        break;
      }
    }
  }
}

void
TorMgr::add_iface(uint16_t port_num, uint32_t ip_addr,
                           const unsigned char (&mac_addr)[6]) {
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::CONTROLLER_STATE);
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::DEVICE_STATE);
}

int
TorMgr::query_counter(const std::string &counter_name, size_t index,
                               uint64_t *packets, uint64_t *bytes) {
  std::promise<p4::CounterData> promise;
  auto future = promise.get_future();
  CounterQueryHandler h(this, counter_name, index, promise);
  post_event(std::move(h));
  future.wait();
  p4::CounterData counter_data = future.get();
  if (counter_data.packet_count() ==
      std::numeric_limits<decltype(counter_data.packet_count())>::max()) return 1;
  *packets = counter_data.packet_count();
  *bytes = counter_data.byte_count();
  return 0;
}

int
TorMgr::query_counter_(const std::string &counter_name, size_t index,
                                p4::CounterData *counter_data) {
  pi_p4_id_t counter_id = pi_p4info_counter_id_from_name(p4info,
                                                         counter_name.c_str());
  if (counter_id == PI_INVALID_ID) {
    std::cout << "Trying to read unknown counter.\n";
    return 1;
  }

  p4::CounterReadRequest request;
  request.set_device_id(dev_id);
  auto entry = request.add_counters();
  entry->set_counter_id(counter_id);
  auto cell = entry->add_cells();
  cell->set_index(index);
  p4::CounterReadResponse rep;
  ClientContext context;
  auto reader = pi_stub_->CounterRead(&context, request);
  while (reader->Read(&rep)) {
    const auto &rep_entry = rep.counter_entry();
    if (rep_entry.counter_id() == entry->counter_id()) {
      for (const auto &rep_cell : rep_entry.cells()) {
        if (rep_cell.index() == cell->index()) {
          counter_data->CopyFrom(rep_cell.data());
          return 0;
        }
      }
    }
  }
  std::cout << "Error when trying to read counter.\n";
  return 1;
}

int
TorMgr::update_config(const std::string &config_buffer) {
  std::promise<int> promise;
  auto future = promise.get_future();
  ConfigUpdateHandler h(this, config_buffer, promise);
  post_event(std::move(h));
  future.wait();
  return future.get();
}

int
TorMgr::update_config_(const std::string &config_buffer) {
  std::cout << "Updating config\n";
  pi_p4info_t *p4info_new;
  pi_add_config(config_buffer.c_str(), PI_CONFIG_TYPE_BMV2_JSON, &p4info_new);
  pi_p4info_t *p4info_prev = p4info;
  p4info = p4info_new;
  pi_destroy_config(p4info_prev);

  ::google::rpc::Status rep;

  {
    ClientContext context;
    p4::tmp::DeviceUpdateStartRequest request;
    request.set_device_id(dev_id);
    char *p4info_json = pi_serialize_config(p4info, 0);
//    request.set_native_p4info_json(p4info_json);
    free(p4info_json);
    request.set_device_data(config_buffer);
    Status status = device_stub_->DeviceUpdateStart(&context, request, &rep);
    assert(status.ok());
    if (rep.code() != ::google::rpc::Code::OK) {
      std::cout << "Error when initiating config update\n";
      return 1;
    }
  }

  set_default_entries();
  static_config_(UpdateMode::DEVICE_STATE);
  // controller state does not change here
  static_config_(UpdateMode::CONTROLLER_STATE);

  {
    ClientContext context;
    p4::tmp::DeviceUpdateEndRequest request;
    request.set_device_id(dev_id);
    Status status = device_stub_->DeviceUpdateEnd(&context, request, &rep);
    assert(status.ok());
    if (rep.code() != ::google::rpc::Code::OK) {
      std::cout << "Error when initiating config update\n";
      return 1;
    }
  }

  return 0;
}