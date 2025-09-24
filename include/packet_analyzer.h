#pragma once

#include <cstdint>
#include <optional>
#include <string>

struct tcphdr;
struct ethhdr;
struct iphdr;

namespace sniffer
{
    struct PacketStats
    {
        uint64_t total_packets = 0;
        uint64_t tcp_packets = 0;
        uint64_t udp_packets = 0;
        uint64_t icmp_packets = 0;
        uint64_t other_packets = 0;
        uint64_t ipv4_packets = 0;
        uint64_t total_bytes = 0;
        uint64_t arp_packets = 0;

        void print() const;
    };

    struct PacketFilter
    {
        // optional - c++17 может как присутствовать так и отсутствовать
        std::optional<std::string> protocol; // tcp udp icmp
        std::optional<std::string> ip_address;
        std::optional<uint16_t> port;
    };

    class PacketAnalyzer
    {
    public:
        // компилятор сгенерирует конструктор по умолчанию
        PacketAnalyzer() = default;

        void analyze_packet(const unsigned char *buffer, int size);
        void set_filter(const PacketFilter &filter);
        void set_verbose(bool verbose);
        void set_quiet(bool quiet) { quiet_mode_ = quiet; }
        const PacketStats &get_stats() const { return stats_; }

    private:
        PacketStats stats_;
        PacketFilter filter_;
        bool verbose_mode_ = false;
        bool quiet_mode_ = false;

        void analyze_ethernet(const unsigned char *buffer, int size);
        void analyze_ipv4(const unsigned char *buffer, int size, size_t eth_offset);
        void analyze_tcp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len);
        void analyze_udp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len);
        void analyze_icmp(const unsigned char *buffer, int size, size_t ip_offset, size_t ip_header_len);

        void print_mac(const char *label, const unsigned char mac[6]) const;
        void print_tcp_flags(const struct tcphdr *tcp) const;

        bool should_show_packet(const unsigned char* buffer, int size) const;
    };
}