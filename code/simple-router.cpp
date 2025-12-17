/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  if (packet.size() < sizeof(ethernet_hdr)) return;

  ethernet_hdr* eth = (ethernet_hdr*)packet.data();
  uint16_t type = ntohs(eth->ether_type);

  if (type == ethertype_arp) {
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(arp_hdr)) return;
    arp_hdr* arp = (arp_hdr*)(packet.data() + sizeof(ethernet_hdr));

    if (ntohs(arp->arp_hrd) != arp_hrd_ethernet ||
        ntohs(arp->arp_pro) != ethertype_ip ||
        arp->arp_hln != ETHER_ADDR_LEN ||
        arp->arp_pln != 4) {
      return;
    }

    uint16_t op = ntohs(arp->arp_op);
    if (op == arp_op_request) {
      uint32_t targetIp = arp->arp_tip;
      const Interface* targetIface = findIfaceByIp(targetIp);
      if (targetIface) {
        Buffer replyPkt(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        ethernet_hdr* replyEth = (ethernet_hdr*)replyPkt.data();
        arp_hdr* replyArp = (arp_hdr*)(replyPkt.data() + sizeof(ethernet_hdr));

        memcpy(replyEth->ether_dhost, arp->arp_sha, ETHER_ADDR_LEN);
        memcpy(replyEth->ether_shost, targetIface->addr.data(), ETHER_ADDR_LEN);
        replyEth->ether_type = htons(ethertype_arp);

        replyArp->arp_hrd = htons(arp_hrd_ethernet);
        replyArp->arp_pro = htons(ethertype_ip);
        replyArp->arp_hln = ETHER_ADDR_LEN;
        replyArp->arp_pln = 4;
        replyArp->arp_op = htons(arp_op_reply);
        memcpy(replyArp->arp_sha, targetIface->addr.data(), ETHER_ADDR_LEN);
        replyArp->arp_sip = targetIface->ip;
        memcpy(replyArp->arp_tha, arp->arp_sha, ETHER_ADDR_LEN);
        replyArp->arp_tip = arp->arp_sip;

        sendPacket(replyPkt, inIface);
      }
    } else if (op == arp_op_reply) {
      uint32_t senderIp = arp->arp_sip;
      Buffer senderMac(arp->arp_sha, arp->arp_sha + ETHER_ADDR_LEN);

      auto req = m_arp.insertArpEntry(senderMac, senderIp);
      if (req) {
        for (const auto& pkt : req->packets) {
          Buffer p = pkt.packet;
          ethernet_hdr* pEth = (ethernet_hdr*)p.data();
          memcpy(pEth->ether_dhost, senderMac.data(), ETHER_ADDR_LEN);

          const Interface* outIface = findIfaceByName(pkt.iface);
          if (outIface) {
            memcpy(pEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
            sendPacket(p, pkt.iface);
          }
        }
      }
    }
  } else if (type == ethertype_ip) {
    if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) return;
    ip_hdr* ip = (ip_hdr*)(packet.data() + sizeof(ethernet_hdr));

    uint16_t sum = ip->ip_sum;
    ip->ip_sum = 0;
    if (cksum(ip, ip->ip_hl * 4) != sum) {
      return;
    }
    ip->ip_sum = sum;

    if (packet.size() < sizeof(ethernet_hdr) + ntohs(ip->ip_len)) return;

    const Interface* destIface = findIfaceByIp(ip->ip_dst);
    if (destIface) {
      if (ip->ip_p == ip_protocol_icmp) {
        size_t ipHeaderLen = ip->ip_hl * 4;
        if (packet.size() < sizeof(ethernet_hdr) + ipHeaderLen + sizeof(icmp_hdr)) return;

        icmp_hdr* icmp = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + ipHeaderLen);
        if (icmp->icmp_type == 8) {
          uint16_t icmpSum = icmp->icmp_sum;
          icmp->icmp_sum = 0;
          size_t icmpLen = ntohs(ip->ip_len) - ipHeaderLen;
          if (cksum(icmp, icmpLen) != icmpSum) return;

          Buffer replyPkt = packet;
          ethernet_hdr* rEth = (ethernet_hdr*)replyPkt.data();
          ip_hdr* rIp = (ip_hdr*)(replyPkt.data() + sizeof(ethernet_hdr));
          icmp_hdr* rIcmp = (icmp_hdr*)(replyPkt.data() + sizeof(ethernet_hdr) + ipHeaderLen);

          rIp->ip_dst = ip->ip_src;
          rIp->ip_src = ip->ip_dst;
          rIp->ip_ttl = 64;
          rIp->ip_sum = 0;
          rIp->ip_sum = cksum(rIp, ipHeaderLen);

          rIcmp->icmp_type = 0;
          rIcmp->icmp_code = 0;
          rIcmp->icmp_sum = 0;
          rIcmp->icmp_sum = cksum(rIcmp, icmpLen);

          try {
            RoutingTableEntry rt = m_routingTable.lookup(rIp->ip_dst);
            uint32_t nextHop = rt.gw ? rt.gw : rIp->ip_dst;
            auto arpEntry = m_arp.lookup(nextHop);

            const Interface* outIface = findIfaceByName(rt.ifName);
            if (outIface) {
              memcpy(rEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
              if (arpEntry) {
                memcpy(rEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
                sendPacket(replyPkt, rt.ifName);
              } else {
                m_arp.queueRequest(nextHop, replyPkt, rt.ifName);
              }
            }
          } catch (...) {}
        }
      } else if (ip->ip_p == 6 || ip->ip_p == 17) {
        // Send ICMP Port Unreachable
        size_t icmpDataLen = sizeof(ip_hdr) + 8;
        size_t totalLen = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
        Buffer icmpPkt(totalLen);

        ethernet_hdr* outEth = (ethernet_hdr*)icmpPkt.data();
        ip_hdr* outIp = (ip_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr));
        icmp_t3_hdr* outIcmp = (icmp_t3_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        try {
          RoutingTableEntry rt = m_routingTable.lookup(ip->ip_src);
          const Interface* outIface = findIfaceByName(rt.ifName);
          if (outIface) {
            uint32_t nextHop = rt.gw ? rt.gw : ip->ip_src;
            auto arpEntry = m_arp.lookup(nextHop);

            if (arpEntry) {
              memcpy(outEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
              memcpy(outEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
              outEth->ether_type = htons(ethertype_ip);

              outIp->ip_v = 4;
              outIp->ip_hl = 5;
              outIp->ip_tos = 0;
              outIp->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
              outIp->ip_id = htons(0);
              outIp->ip_off = htons(IP_DF);
              outIp->ip_ttl = 64;
              outIp->ip_p = ip_protocol_icmp;
              outIp->ip_sum = 0;
              outIp->ip_src = destIface->ip; // Use the destination IP as source
              outIp->ip_dst = ip->ip_src;
              outIp->ip_sum = cksum(outIp, sizeof(ip_hdr));

              outIcmp->icmp_type = 3;
              outIcmp->icmp_code = 3;
              outIcmp->icmp_sum = 0;
              outIcmp->unused = 0;
              outIcmp->next_mtu = 0;
              memcpy(outIcmp->data, ip, icmpDataLen);
              outIcmp->icmp_sum = cksum(outIcmp, sizeof(icmp_t3_hdr));

              sendPacket(icmpPkt, rt.ifName);
            }
          }
        } catch (...) {}
      }
    } else {
      if (ip->ip_ttl <= 1) {
        // Send ICMP Time Exceeded
        size_t icmpDataLen = sizeof(ip_hdr) + 8;
        size_t totalLen = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
        Buffer icmpPkt(totalLen);

        ethernet_hdr* outEth = (ethernet_hdr*)icmpPkt.data();
        ip_hdr* outIp = (ip_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr));
        icmp_t3_hdr* outIcmp = (icmp_t3_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        try {
          RoutingTableEntry rt = m_routingTable.lookup(ip->ip_src);
          const Interface* outIface = findIfaceByName(rt.ifName);
          if (outIface) {
            uint32_t nextHop = rt.gw ? rt.gw : ip->ip_src;
            auto arpEntry = m_arp.lookup(nextHop);

            if (arpEntry) {
              memcpy(outEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
              memcpy(outEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
              outEth->ether_type = htons(ethertype_ip);

              outIp->ip_v = 4;
              outIp->ip_hl = 5;
              outIp->ip_tos = 0;
              outIp->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
              outIp->ip_id = htons(0);
              outIp->ip_off = htons(IP_DF);
              outIp->ip_ttl = 64;
              outIp->ip_p = ip_protocol_icmp;
              outIp->ip_sum = 0;
              outIp->ip_src = iface->ip; // Use incoming interface IP
              outIp->ip_dst = ip->ip_src;
              outIp->ip_sum = cksum(outIp, sizeof(ip_hdr));

              outIcmp->icmp_type = 11;
              outIcmp->icmp_code = 0;
              outIcmp->icmp_sum = 0;
              outIcmp->unused = 0;
              outIcmp->next_mtu = 0;
              memcpy(outIcmp->data, ip, icmpDataLen);
              outIcmp->icmp_sum = cksum(outIcmp, sizeof(icmp_t3_hdr));

              sendPacket(icmpPkt, rt.ifName);
            }
          }
        } catch (...) {}
        return;
      }

      ip->ip_ttl--;
      ip->ip_sum = 0;
      ip->ip_sum = cksum(ip, ip->ip_hl * 4);

      try {
        RoutingTableEntry rt = m_routingTable.lookup(ip->ip_dst);
        uint32_t nextHop = rt.gw ? rt.gw : ip->ip_dst;
        auto arpEntry = m_arp.lookup(nextHop);

        const Interface* outIface = findIfaceByName(rt.ifName);
        if (outIface) {
          Buffer fwdPkt = packet;
          ethernet_hdr* fEth = (ethernet_hdr*)fwdPkt.data();
          memcpy(fEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

          if (arpEntry) {
            memcpy(fEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
            sendPacket(fwdPkt, rt.ifName);
          } else {
            m_arp.queueRequest(nextHop, fwdPkt, rt.ifName);
          }
        }
      } catch (...) {
        // Send ICMP Net Unreachable
        size_t icmpDataLen = sizeof(ip_hdr) + 8;
        size_t totalLen = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
        Buffer icmpPkt(totalLen);

        ethernet_hdr* outEth = (ethernet_hdr*)icmpPkt.data();
        ip_hdr* outIp = (ip_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr));
        icmp_t3_hdr* outIcmp = (icmp_t3_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

        try {
          RoutingTableEntry rt = m_routingTable.lookup(ip->ip_src);
          const Interface* outIface = findIfaceByName(rt.ifName);
          if (outIface) {
            uint32_t nextHop = rt.gw ? rt.gw : ip->ip_src;
            auto arpEntry = m_arp.lookup(nextHop);

            if (arpEntry) {
              memcpy(outEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
              memcpy(outEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
              outEth->ether_type = htons(ethertype_ip);

              outIp->ip_v = 4;
              outIp->ip_hl = 5;
              outIp->ip_tos = 0;
              outIp->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
              outIp->ip_id = htons(0);
              outIp->ip_off = htons(IP_DF);
              outIp->ip_ttl = 64;
              outIp->ip_p = ip_protocol_icmp;
              outIp->ip_sum = 0;
              outIp->ip_src = iface->ip; // Use incoming interface IP
              outIp->ip_dst = ip->ip_src;
              outIp->ip_sum = cksum(outIp, sizeof(ip_hdr));

              outIcmp->icmp_type = 3;
              outIcmp->icmp_code = 0;
              outIcmp->icmp_sum = 0;
              outIcmp->unused = 0;
              outIcmp->next_mtu = 0;
              memcpy(outIcmp->data, ip, icmpDataLen);
              outIcmp->icmp_sum = cksum(outIcmp, sizeof(icmp_t3_hdr));

              sendPacket(icmpPkt, rt.ifName);
            }
          }
        } catch (...) {}
      }
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
