#include "packet_analyzer.h"
#include "format.h"
#include "hex_utils.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

namespace sniffer
{
    // Простые сеттеры
    void PacketAnalyzer::set_filter(const PacketFilter &filter) { filter_ = filter; }
    void PacketAnalyzer::set_verbose(bool verbose) { verbose_mode_ = verbose; }

    void PacketStats::print() const
    {
        std::cout << "\n"
                  << Format::bold() << Format::green()
                  << "=== СТАТИСТИКА ПАКЕТОВ ===" << Format::reset() << "\n";
        std::cout << "Всего пакетов: " << Format::bold() << total_packets << Format::reset() << "\n";
        std::cout << "IPv4 пакетов:  " << ipv4_packets << "\n";
        std::cout << "TCP пакетов:   " << Format::green() << tcp_packets << Format::reset() << "\n";
        std::cout << "UDP пакетов:   " << Format::blue() << udp_packets << Format::reset() << "\n";
        std::cout << "ICMP пакетов:  " << Format::yellow() << icmp_packets << Format::reset() << "\n";
        std::cout << "ARP пакетов:   " << arp_packets << "\n";
        std::cout << "Прочие пакеты: " << other_packets << "\n";
        std::cout << "Общий объём:   " << total_bytes << " байт\n";
    }

    void PacketAnalyzer::analyze_packet(const unsigned char *buffer, int size)
    {
        if (!buffer)
        {
            std::cerr << "Пустой буфер\n";
            return;
        }

        if (size < static_cast<int>(sizeof(ethhdr)))
        {
            if (!quiet_mode_)
                std::cerr << "Слишком маленький пакет: " << size << " байт\n";
            return;
        }
        stats_.total_packets++;
        stats_.total_bytes += static_cast<uint64_t>(size);

        if (verbose_mode_ && !quiet_mode_)
        {
            std::cout << Format::yellow() << "\n--- Пакет #" << stats_.total_packets
                      << " (" << size << " байт) ---" << Format::reset() << "\n";
        }

        analyze_ethernet(buffer, size);

        if (verbose_mode_ && !quiet_mode_)
        {
            // Показываем hex dump только в verbose режиме
            std::cout << Format::blue() << "Hex dump:" << Format::reset() << "\n";
            sniffer::hex_dump(buffer, static_cast<size_t>(size));
        }
    }

    void PacketAnalyzer::analyze_ethernet(const unsigned char *buffer, int size)
    {
        struct ethhdr eth{};
        std::memcpy(&eth, buffer, sizeof(eth));
        if (verbose_mode_ && !quiet_mode_)
        {
            print_mac("MAC отправителя", eth.h_source);
            print_mac("MAC получателя", eth.h_dest);
        }

        // порядок сетевой -> хосотовый
        uint16_t ether_type = ntohs(eth.h_proto);
        if (verbose_mode_ && !quiet_mode_)
            std::cout << "EtherType: " << Format::blue() << "0x" << std::hex << ether_type;

        size_t l3_offset = sizeof(struct ethhdr);
        // VLAN 802.1Q/802.1AD поддержка (минимум один тег)
        if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD)
        {
            if (size < static_cast<int>(l3_offset + 4))
            {
                if (!quiet_mode_)
                    std::cout << " (VLAN, усечён)" << Format::reset() << "\n";
                return;
            }
            uint16_t inner_be{};
            std::memcpy(&inner_be, buffer + l3_offset + 2, sizeof(inner_be));
            const uint16_t inner_type = ntohs(inner_be);
            ether_type = inner_type;
            l3_offset += 4;
        }

        if (ether_type == ETH_P_IP)
        {
            if (verbose_mode_ && !quiet_mode_)
                std::cout << " (IPv4)" << Format::reset() << "\n";
            analyze_ipv4(buffer, size, l3_offset);
            stats_.ipv4_packets++;
        }
        else if (ether_type == ETH_P_ARP)
        {
            if (verbose_mode_ && !quiet_mode_)
                std::cout << " (ARP)" << Format::reset() << "\n";
            // Если задан фильтр по L4-протоколу (tcp/udp/icmp),
            // не засоряем вывод ARP-кадрами в обычном режиме
            if (!verbose_mode_ && !quiet_mode_ && !filter_.protocol.has_value())
            {
                std::cout << "ARP frame, len=" << size << "\n";
            }
            stats_.arp_packets++;
        }
        else
        {
            if (verbose_mode_ && !quiet_mode_)
                std::cout << " (Unknown)" << Format::reset() << "\n";
            // При активном фильтре по L4-протоколу скрываем прочие L2 кадры в обычном режиме
            if (!verbose_mode_ && !quiet_mode_ && !filter_.protocol.has_value())
            {
                std::cout << "ETH type=0x" << std::hex << ether_type << std::dec
                          << ", len=" << size << "\n";
            }
            stats_.other_packets++;
        }
        std::cout << std::dec;
    }

    void PacketAnalyzer::print_mac(const char *label, const unsigned char mac[6]) const
    {
        std::cout << label << ": " << Format::magenta();
        for (int i = 0; i < 6; i++)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << static_cast<int>(mac[i]);
            if (i < 5)
                std::cout << ":";
        }
        std::cout << Format::reset() << "\n"
                  << std::dec;
    }

    void PacketAnalyzer::analyze_ipv4(const unsigned char *buffer, int size, size_t eth_offset)
    {
        if (size < static_cast<int>(eth_offset + sizeof(struct iphdr)))
        {
            if (!quiet_mode_)
                std::cout << "Пакет усечён: нет полного IP заголовка\n";
            return;
        }

        // сдвигаем указатель на размер ethernet заголовка чтобы попасть на IP заголовок
        // указатель приводим к iphdr
        struct iphdr ip{};
        std::memcpy(&ip, buffer + eth_offset, sizeof(ip));
        const size_t ip_hlen = ip.ihl * 4;

        // ihl - internet header length - длина ip заголовка
        // 32 бита слово умножаем и получаем всю длинну в байтах
        if (ip_hlen < sizeof(struct iphdr) || size < static_cast<int>(eth_offset + ip_hlen))
        {
            if (!quiet_mode_)
                std::cout << "Некорректная длина IP заголовка:" << ip_hlen << "\n";
            return;
        }

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        // переводим ip адрес в человекочитаемый формат
        inet_ntop(AF_INET, &ip.saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip.daddr, dst_ip, sizeof(dst_ip));

        if (verbose_mode_ && !quiet_mode_)
        {
            std::cout << "IP: " << Format::green() << src_ip << Format::reset()
                      << " -> " << Format::green() << dst_ip << Format::reset() << "\n";
            std::cout << "Protocol: " << Format::l4_color(ip.protocol)
                      << Format::l4_name(ip.protocol) << Format::reset()
                      << ", TTL: " << static_cast<int>(ip.ttl) // время жизни
                      << ", IHL: " << ip_hlen                  // длинна заголовка в 32 битных поолях
                      << "\n";
        }

        // Фильтрация на уровне IP-адреса после вычисления корректных смещений
        if (filter_.ip_address.has_value())
        {
            // сравнение src или dst текстово
            bool ip_match = false;
            if (filter_.ip_address.value() == src_ip || filter_.ip_address.value() == dst_ip)
                ip_match = true;
            if (!ip_match)
                return; // не показываем/не считаем L4, но общий счётчик уже увеличен в analyze_packet
        }

        // Фрагментация: если смещение фрагмента > 0 — не парсим L4
        const uint16_t frag_off = ntohs(ip.frag_off);
        const uint16_t frag_offset8 = frag_off & 0x1FFF; // младшие 13 бит
        if (frag_offset8 > 0)
        {
            if (!quiet_mode_)
                std::cout << "IPv4 fragment (offset>0), L4 не парсим\n";
            return;
        }

        // Фильтр по протоколу (после корректного вычисления смещений)
        if (filter_.protocol.has_value())
        {
            const std::string &pf = filter_.protocol.value();
            if ((pf == "tcp" && ip.protocol != IPPROTO_TCP) ||
                (pf == "udp" && ip.protocol != IPPROTO_UDP) ||
                (pf == "icmp" && ip.protocol != IPPROTO_ICMP))
            {
                return;
            }
        }

        // Анализируем транспортный уровень
        if (ip.protocol == IPPROTO_TCP)
        {
            stats_.tcp_packets++;
            if (verbose_mode_)
            {
                analyze_tcp(buffer, size, eth_offset, ip_hlen);
            }
            else if (!quiet_mode_)
            {
                const size_t tcp_offset = eth_offset + ip_hlen;
                if (size >= static_cast<int>(tcp_offset + sizeof(struct tcphdr)))
                {
                    struct tcphdr tcp_local{};
                    std::memcpy(&tcp_local, buffer + tcp_offset, sizeof(tcp_local));
                    const uint16_t sport = ntohs(tcp_local.source);
                    const uint16_t dport = ntohs(tcp_local.dest);
                    if (filter_.port.has_value() && !(sport == filter_.port.value() || dport == filter_.port.value()))
                        return;
                    std::cout << "TCP " << src_ip << ":" << sport << " -> " << dst_ip << ":" << dport
                              << " TTL=" << static_cast<int>(ip.ttl) << " IHL=" << ip_hlen << "\n";
                }
                else
                {
                    std::cout << "TCP " << src_ip << " -> " << dst_ip << " (усечён TCP заголовок)\n";
                }
            }
        }
        else if (ip.protocol == IPPROTO_UDP)
        {
            stats_.udp_packets++;
            if (verbose_mode_)
            {
                analyze_udp(buffer, size, eth_offset, ip_hlen);
            }
            else if (!quiet_mode_)
            {
                const size_t udp_offset = eth_offset + ip_hlen;
                if (size >= static_cast<int>(udp_offset + sizeof(struct udphdr)))
                {
                    struct udphdr udp_local{};
                    std::memcpy(&udp_local, buffer + udp_offset, sizeof(udp_local));
                    const uint16_t sport = ntohs(udp_local.source);
                    const uint16_t dport = ntohs(udp_local.dest);
                    if (filter_.port.has_value() && !(sport == filter_.port.value() || dport == filter_.port.value()))
                        return;
                    std::cout << "UDP " << src_ip << ":" << sport << " -> " << dst_ip << ":" << dport
                              << " TTL=" << static_cast<int>(ip.ttl) << " IHL=" << ip_hlen
                              << " LEN=" << ntohs(udp_local.len) << "\n";
                }
                else
                {
                    std::cout << "UDP " << src_ip << " -> " << dst_ip << " (усечён UDP заголовок)\n";
                }
            }
        }
        else if (ip.protocol == IPPROTO_ICMP)
        {
            stats_.icmp_packets++;
            if (verbose_mode_)
            {
                analyze_icmp(buffer, size, eth_offset, ip_hlen);
            }
            else if (!quiet_mode_)
            {
                const size_t icmp_offset = eth_offset + ip_hlen;
                if (size >= static_cast<int>(icmp_offset + sizeof(struct icmphdr)))
                {
                    struct icmphdr icmp_local{};
                    std::memcpy(&icmp_local, buffer + icmp_offset, sizeof(icmp_local));
                    std::cout << "ICMP " << src_ip << " -> " << dst_ip
                              << " type=" << static_cast<int>(icmp_local.type)
                              << " code=" << static_cast<int>(icmp_local.code)
                              << " TTL=" << static_cast<int>(ip.ttl) << " IHL=" << ip_hlen << "\n";
                }
                else
                {
                    std::cout << "ICMP " << src_ip << " -> " << dst_ip << " (усечён ICMP заголовок)\n";
                }
            }
        }
        else
        {
            stats_.other_packets++;
            if (!quiet_mode_ && !verbose_mode_)
            {
                std::cout << "IPv4 " << Format::l4_name(ip.protocol) << " "
                          << src_ip << " -> " << dst_ip
                          << " TTL=" << static_cast<int>(ip.ttl) << " IHL=" << ip_hlen << "\n";
            }
        }
    }

    void PacketAnalyzer::analyze_tcp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len)
    {
        const size_t tcp_offset = ip_offset + ip_header_len;

        if (size < static_cast<int>(tcp_offset + sizeof(struct tcphdr)))
        {
            std::cout << "Пакет усечён: нет полного TCP заголовка\n";
            return;
        }

        struct tcphdr tcp{};
        std::memcpy(&tcp, buffer + tcp_offset, sizeof(tcp));

        // Проверка data offset (длина TCP заголовка в 32-битных словах)
        const size_t tcp_hlen = static_cast<size_t>(tcp.doff) * 4;
        if (tcp_hlen < sizeof(struct tcphdr) || size < static_cast<int>(tcp_offset + tcp_hlen))
        {
            if (!quiet_mode_)
                std::cout << "Пакет усечён: некорректная длина TCP заголовка\n";
            return;
        }

        // Фильтр по порту, если задан, применяется для TCP/UDP
        if (filter_.port.has_value())
        {
            const uint16_t srcp = ntohs(tcp.source);
            const uint16_t dstp = ntohs(tcp.dest);
            if (!(srcp == filter_.port.value() || dstp == filter_.port.value()))
                return;
        }

        if (!quiet_mode_)
        {
            std::cout << Format::green() << "TCP: " << Format::reset()
                      << ntohs(tcp.source) << " -> " << ntohs(tcp.dest)
                      << " (hdr=" << tcp_hlen << ")\n";

            print_tcp_flags(&tcp);

            std::cout << "Seq: " << ntohl(tcp.seq) << ", Ack: " << ntohl(tcp.ack_seq)
                      << ", Window: " << ntohs(tcp.window) << "\n";
        }
    }

    void PacketAnalyzer::analyze_udp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len)
    {
        const size_t udp_offset = ip_offset + ip_header_len;

        if (size < static_cast<int>(udp_offset + sizeof(struct udphdr)))
        {
            if (!quiet_mode_)
                std::cout << "Пакет усечён: нет полного UDP заголовка\n";
            return;
        }

        struct udphdr udp{};
        std::memcpy(&udp, buffer + udp_offset, sizeof(udp));

        // Проверка согласованности длины UDP
        const uint16_t udp_len = ntohs(udp.len);
        if (udp_len < sizeof(struct udphdr) || static_cast<int>(udp_offset + udp_len) > size)
        {
            if (!quiet_mode_)
                std::cout << "Пакет усечён: некорректная длина UDP\n";
            return;
        }

        if (filter_.port.has_value())
        {
            const uint16_t srcp = ntohs(udp.source);
            const uint16_t dstp = ntohs(udp.dest);
            if (!(srcp == filter_.port.value() || dstp == filter_.port.value()))
                return;

            std::cout << Format::blue() << "UDP: " << Format::reset()
                      << ntohs(udp.source) << " -> " << ntohs(udp.dest)
                      << " (len=" << udp_len << ")\n";
        }
    }

    void PacketAnalyzer::analyze_icmp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len)
    {
        const size_t icmp_offset = ip_offset + ip_header_len;

        if (size < static_cast<int>(icmp_offset + sizeof(struct icmphdr)))
        {
            if (!quiet_mode_)
                std::cout << "Пакет усечён: нет полного ICMP заголовка\n";
            return;
        }

        struct icmphdr icmp{};
        std::memcpy(&icmp, buffer + icmp_offset, sizeof(icmp));

        if (!quiet_mode_)
        {
            std::cout << Format::yellow() << "ICMP: " << Format::reset()
                      << "type=" << static_cast<int>(icmp.type)
                      << " code=" << static_cast<int>(icmp.code);

            // Расшифровываем популярные ICMP типы
            switch (icmp.type)
            {
            case 0:
                std::cout << " (Echo Reply)";
                break;
            case 3:
                std::cout << " (Destination Unreachable)";
                break;
            case 8:
                std::cout << " (Echo Request/Ping)";
                break;
            case 11:
                std::cout << " (Time Exceeded)";
                break;
            default:
                std::cout << " (Unknown)";
                break;
            }
            std::cout << "\n";
        }
    }

    void PacketAnalyzer::print_tcp_flags(const struct tcphdr *tcp) const
    {
        if (quiet_mode_)
            return;
        std::cout << "TCP Flags: ";
        if (tcp->urg)
            std::cout << Format::magenta() << "URG " << Format::reset();
        if (tcp->ack)
            std::cout << Format::green() << "ACK " << Format::reset();
        if (tcp->psh)
            std::cout << Format::blue() << "PSH " << Format::reset();
        if (tcp->rst)
            std::cout << Format::yellow() << "RST " << Format::reset();
        if (tcp->syn)
            std::cout << Format::green() << "SYN " << Format::reset();
        if (tcp->fin)
            std::cout << Format::yellow() << "FIN " << Format::reset();
        std::cout << "\n";
    }
    bool PacketAnalyzer::should_show_packet(const unsigned char *buffer, int size) const
    {
        // Перенесли фактическую фильтрацию ниже (в analyze_ipv4/TCP/UDP)
        // Здесь оставим предфильтр по протоколу, если можем быстро определить
        if (!filter_.protocol.has_value())
            return true;

        if (!buffer || size < static_cast<int>(sizeof(ethhdr)))
            return true;

        struct ethhdr eth{};
        std::memcpy(&eth, buffer, sizeof(eth));
        uint16_t et = ntohs(eth.h_proto);
        size_t l3 = sizeof(struct ethhdr);
        if (et == ETH_P_8021Q || et == ETH_P_8021AD)
        {
            if (size < static_cast<int>(l3 + 4))
                return true;
            uint16_t inner_be{};
            std::memcpy(&inner_be, buffer + l3 + 2, sizeof(inner_be));
            et = ntohs(inner_be);
            l3 += 4;
        }
        if (et != ETH_P_IP)
            return true;
        if (size < static_cast<int>(l3 + sizeof(struct iphdr)))
            return true;
        struct iphdr ip{};
        std::memcpy(&ip, buffer + l3, sizeof(ip));
        const std::string &pf = filter_.protocol.value();
        if (pf == "tcp" && ip.protocol != IPPROTO_TCP)
            return false;
        if (pf == "udp" && ip.protocol != IPPROTO_UDP)
            return false;
        if (pf == "icmp" && ip.protocol != IPPROTO_ICMP)
            return false;
        return true;
    }
}