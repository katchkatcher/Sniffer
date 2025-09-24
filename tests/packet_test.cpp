#include <cassert>
#include <cstring>
#include <vector>
#include <netinet/in.h>
#include "packet_analyzer.h"

// Создаем минимальный валидный Ethernet + IP пакет
std::vector<uint8_t> create_test_packet()
{
    std::vector<uint8_t> packet;

    // Ethernet header (14 bytes)
    packet.resize(14 + 20); // Eth + IP минимум

    // Заполняем минимальные поля для тестирования
    packet[12] = 0x08; // EtherType high byte
    packet[13] = 0x00; // EtherType low byte (IPv4)

    // IP header version и length
    packet[14] = 0x45;            // version=4, IHL=5
    packet[14 + 9] = IPPROTO_TCP; // protocol

    return packet;
}

int main()
{
    sniffer::PacketAnalyzer analyzer;

    auto packet = create_test_packet();

    // Тест на валидный пакет
    analyzer.analyze_packet(packet.data(), static_cast<int>(packet.size()));

    // Тест на нулевой указатель
    analyzer.analyze_packet(nullptr, 100);

    // Тест на слишком маленький пакет
    analyzer.analyze_packet(packet.data(), 5);

    const auto &stats = analyzer.get_stats();
    (void)stats;
    assert(stats.total_packets == 1); // Только валидный пакет учтен

    std::puts("packet_test ok");
    return 0;
}