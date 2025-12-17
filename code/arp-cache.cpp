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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto now = steady_clock::now();

  // Check ARP requests
  for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); ) {
    auto& req = *it;
    auto duration = std::chrono::duration_cast<seconds>(now - req->timeSent);

    if (duration.count() >= 1) {
      if (req->nTimesSent >= MAX_SENT_TIME) {
        // Send ICMP Host Unreachable to all waiting packets
        for (const auto& pkt : req->packets) {
          if (pkt.packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr)) continue;

          ethernet_hdr* eth = (ethernet_hdr*)pkt.packet.data();
          ip_hdr* ip = (ip_hdr*)(pkt.packet.data() + sizeof(ethernet_hdr));

          try {
            RoutingTableEntry rt = m_router.getRoutingTable().lookup(ip->ip_src);
            const Interface* outIface = m_router.findIfaceByName(rt.ifName);
            if (!outIface) continue;

            uint32_t nextHop = rt.gw ? rt.gw : ip->ip_src;
            auto arpEntry = lookup(nextHop);
            
            if (arpEntry) {
              size_t icmpDataLen = sizeof(ip_hdr) + 8;
              size_t totalLen = sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_t3_hdr);
              Buffer icmpPkt(totalLen);

              ethernet_hdr* outEth = (ethernet_hdr*)icmpPkt.data();
              ip_hdr* outIp = (ip_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr));
              icmp_t3_hdr* outIcmp = (icmp_t3_hdr*)(icmpPkt.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

              // Ethernet Header
              memcpy(outEth->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
              memcpy(outEth->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
              outEth->ether_type = htons(ethertype_ip);

              // IP Header
              outIp->ip_v = 4;
              outIp->ip_hl = 5;
              outIp->ip_tos = 0;
              outIp->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
              outIp->ip_id = htons(0);
              outIp->ip_off = htons(IP_DF);
              outIp->ip_ttl = 64;
              outIp->ip_p = ip_protocol_icmp;
              outIp->ip_sum = 0;
              outIp->ip_src = outIface->ip;
              outIp->ip_dst = ip->ip_src;
              outIp->ip_sum = cksum(outIp, sizeof(ip_hdr));

              // ICMP Header
              outIcmp->icmp_type = 3; // Dest Unreachable
              outIcmp->icmp_code = 1; // Host Unreachable
              outIcmp->icmp_sum = 0;
              outIcmp->unused = 0;
              outIcmp->next_mtu = 0;
              memcpy(outIcmp->data, ip, icmpDataLen);
              outIcmp->icmp_sum = cksum(outIcmp, sizeof(icmp_t3_hdr));

              m_router.sendPacket(icmpPkt, rt.ifName);
            }
          } catch (...) {
            // Route not found
          }
        }
        it = m_arpRequests.erase(it);
      } else {
        // Send ARP Request
        if (!req->packets.empty()) {
          std::string ifaceName = req->packets.front().iface;
          const Interface* iface = m_router.findIfaceByName(ifaceName);
          if (iface) {
            Buffer arpPkt(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            ethernet_hdr* eth = (ethernet_hdr*)arpPkt.data();
            arp_hdr* arp = (arp_hdr*)(arpPkt.data() + sizeof(ethernet_hdr));

            // Ethernet Header
            memset(eth->ether_dhost, 0xFF, ETHER_ADDR_LEN);
            memcpy(eth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
            eth->ether_type = htons(ethertype_arp);

            // ARP Header
            arp->arp_hrd = htons(arp_hrd_ethernet);
            arp->arp_pro = htons(ethertype_ip);
            arp->arp_hln = ETHER_ADDR_LEN;
            arp->arp_pln = 4;
            arp->arp_op = htons(arp_op_request);
            memcpy(arp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
            arp->arp_sip = iface->ip;
            memset(arp->arp_tha, 0x00, ETHER_ADDR_LEN);
            arp->arp_tip = req->ip;

            m_router.sendPacket(arpPkt, ifaceName);

            req->timeSent = now;
            req->nTimesSent++;
          }
        }
        ++it;
      }
    } else {
      ++it;
    }
  }

  // Check ARP cache entries
  for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ) {
    auto duration = std::chrono::duration_cast<seconds>(now - (*it)->timeAdded);
    if (duration >= SR_ARPCACHE_TO) {
      it = m_cacheEntries.erase(it);
    } else {
      ++it;
    }
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    // periodicCheckArpRequestsAndCacheEntries() handles locking;
    // avoid double-locking m_mutex in this thread.
    periodicCheckArpRequestsAndCacheEntries();
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
