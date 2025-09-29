#include <cassert>
#include <vector>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include "packet_analyzer.h"

// минимальный Ethernet + IPv6 + TCP заголовок (без опций)
static std::vector<uint8_t> create_ipv6_tcp_packet()
{
    std::vector<uint8_t> p;
    const size_t eth_len = 14;
    const size_t ip6_len = 40; // базовый заголовок IPv6
    const size_t tcp_len = 20; // минимальный TCP
    p.resize(eth_len + ip6_len + tcp_len, 0);

    // EtherType = 0x86DD (IPv6)
    p[12] = 0x86;
    p[13] = 0xDD;

    // IPv6 версия (4 бита) = 6. Первая 32-битная группа: версия(4) + трафик класс(8) + flow label(20)
    p[14] = 0x60; // 0110 ....
    // Payload length (2 байта) = tcp_len
    uint16_t payload_len = htons(static_cast<uint16_t>(tcp_len));
    std::memcpy(&p[14 + 4], &payload_len, sizeof(payload_len));
    // Next Header = TCP (6)
    p[14 + 6] = IPPROTO_TCP;
    // Hop Limit
    p[14 + 7] = 64;
    // Src/Dst IPv6 — оставим ::1 -> ::1
    p[14 + 8 + 15] = 1;  // src ::1
    p[14 + 24 + 15] = 1; // dst ::1

    // TCP header (source/dest ports)
    size_t tcp_off = eth_len + ip6_len;
    uint16_t sport = htons(12345);
    uint16_t dport = htons(80);
    std::memcpy(&p[tcp_off], &sport, 2);
    std::memcpy(&p[tcp_off + 2], &dport, 2);
    // Data offset
    p[tcp_off + 12] = (5 << 4);

    return p;
}

int main()
{
    sniffer::PacketAnalyzer analyzer;
    auto packet = create_ipv6_tcp_packet();
    analyzer.analyze_packet(packet.data(), static_cast<int>(packet.size()));

    const auto &s = analyzer.get_stats();
    assert(s.total_packets == 1);
    assert(s.ipv6_packets == 1);
    assert(s.tcp_packets == 1);

    return 0;
}
