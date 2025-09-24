#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <errno.h>
#include <iostream>
#include <cstring>

#include "packet_analyzer.h"
#include "hex_utils.h"
#include "format.h"
#include "cli_parser.h"

volatile sig_atomic_t stop = 0;
sniffer::PacketAnalyzer analyzer;

// сигнал завершения программы
void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
    std::cout << "\n"
              << Format::yellow() << "Получен сигнал завершения..." << Format::reset() << "\n";
}

// Красивый заголовок ASCII
void print_header()
{
    FILE *header_file = fopen("docs/header.txt", "r");
    if (header_file == nullptr)
    {
        std::cout << Format::green() << "=== Network Packet Analyzer ===" << Format::reset() << "\n";
        std::cout << "Заголовочный файл не найден, используем стандартный заголовок\n";
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), header_file) != nullptr)
    {
        std::cout << Format::green() << buffer << Format::reset();
    }
    fclose(header_file);
    std::cout << "\n";
}

int main(int argc, char *argv[])
{
    CliOptions options = CliParser::parse(argc, argv);

    // Настраиваем фильтры
    sniffer::PacketFilter filter;
    filter.protocol = options.protocol_filter;
    filter.ip_address = options.ip_filter;
    filter.port = options.port_filter;

    analyzer.set_filter(filter);
    analyzer.set_verbose(options.verbose);
    analyzer.set_quiet(options.stats_only);

    print_header();

    // установка обработчиков сигналов
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // создание raw socket
    // AF_PACKET/SOCK_RAW/ETH_P_ALL - получаем L2 кадры (включая Ethernet заголовки)
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("Ошибка создания сокета");
        if (errno == EPERM || errno == EACCES)
        {
            std::cout << Format::yellow() << "Требуются права root или capability CAP_NET_RAW.\n"
                                             "Варианты:\n"
                                             "   sudo ./build/Sniffer\n"
                                             "   или: sudo setcap cap_net_raw,cap_net_admin+eip ./build/Sniffer"
                      << Format::reset() << "\n";
        }
        return 1;
    }

    // Опциональная привязка к интерфейсу
    if (!options.interface.empty())
    {
        struct sockaddr_ll sll{};
        std::memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = if_nametoindex(options.interface.c_str());
        if (sll.sll_ifindex == 0)
        {
            std::cerr << "Неизвестный интерфейс: " << options.interface << "\n";
            close(sockfd);
            return 1;
        }
        if (bind(sockfd, reinterpret_cast<struct sockaddr *>(&sll), sizeof(sll)) < 0)
        {
            perror("bind к интерфейсу не удался");
            close(sockfd);
            return 1;
        }
    }

    if (!options.stats_only)
        std::cout << Format::green() << "Сниффер запущен. Нажмите Ctrl+C для завершения работы." << Format::reset() << "\n\n";

    while (!stop)
    {
        unsigned char buffer[65536];

        // метаданные канального уровня(пакеты Ethernet)
        struct sockaddr_ll addr;
        socklen_t addrlen = sizeof(addr);
        // будем фильтровать и получать только данные канального уровня
        int size = recvfrom(sockfd, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&addr), &addrlen);

        if (size < 0)
        {
            if (!stop)
            {
                perror("Ошибка приёма пакета");
            }
            break;
        }

        // если не eth пакет
        if (addr.sll_hatype != ARPHRD_ETHER)
        {
            // просто скипаем
            continue;
        }

        if (!options.stats_only && options.verbose)
        {
            // выводим имя интерфейса и тип пакета
            char ifname[IF_NAMESIZE] = {0};
            if_indextoname(addr.sll_ifindex, ifname);
            std::cout << Format::blue() << "Interface: " << ifname
                      << ", Type: " << addr.sll_pkttype
                      << ", Protocol: 0x" << std::hex << ntohs(addr.sll_protocol)
                      << std::dec << Format::reset() << "\n";
        }

        if (size > 0 && !stop)
        {
            // Применяем фильтры и анализируем
            analyzer.analyze_packet(buffer, size);

        }
    }

    analyzer.get_stats().print();

    std::cout << Format::green() << "Корректно закрываем сокет..." << Format::reset() << "\n";
    close(sockfd);

    return 0;
}