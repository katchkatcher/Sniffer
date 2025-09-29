#include "cli_parser.h"
#include <iostream>
#include <cstring>
#include <algorithm>

CliOptions CliParser::parse(int argc, const char *const argv[])
{
    CliOptions options;

    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            print_help();
            std::exit(0);
        }
        else if (arg == "-v" || arg == "--verbose")
        {
            options.verbose = true;
        }
        else if (arg == "-s" || arg == "--stats")
        {
            options.stats_only = true;
        }
        else if (arg == "-i" || arg == "--interface")
        {
            if (i + 1 < argc)
            {
                options.interface = argv[++i];
            }
            else
            {
                std::cerr << "Ошибка: --interface требует аргумент\n";
                std::exit(1);
            }
        }
        else if (arg == "-p" || arg == "--protocol")
        {
            if (i + 1 < argc)
            {
                std::string proto = argv[++i];
                std::transform(proto.begin(), proto.end(), proto.begin(), ::tolower);
                if (proto == "tcp" || proto == "udp" || proto == "icmp" || proto == "icmpv6")
                {
                    options.protocol_filter = proto;
                }
                else
                {
                    std::cerr << "Ошибка: неподдерживаемый протокол: " << proto << "\n";
                    std::cerr << "Поддерживаемые: tcp, udp, icmp, icmpv6\n";
                    std::exit(1);
                }
            }
            else
            {
                std::cerr << "Ошибка: --protocol требует аргумент\n";
                std::exit(1);
            }
        }
        else if (arg == "--ip")
        {
            if (i + 1 < argc)
            {
                options.ip_filter = argv[++i];
            }
            else
            {
                std::cerr << "Ошибка: --ip требует аргумент\n";
                std::exit(1);
            }
        }
        else if (arg == "--port")
        {
            if (i + 1 < argc)
            {
                char *endptr;
                long port = std::strtol(argv[++i], &endptr, 10);
                if (*endptr != '\0' || port <= 0 || port > 65535)
                {
                    std::cerr << "Ошибка: некорректный номер порта: " << argv[i] << "\n";
                    std::exit(1);
                }
                options.port_filter = static_cast<uint16_t>(port);
            }
            else
            {
                std::cerr << "Ошибка: --port требует аргумент\n";
                std::exit(1);
            }
        }
        else
        {
            std::cerr << "Ошибка: неизвестный аргумент: " << arg << "\n";
            print_help();
            std::exit(1);
        }
    }

    return options;
}

void CliParser::print_help()
{
    std::cout << R"(Network Packet Sniffer

ИСПОЛЬЗОВАНИЕ:
    sniffer [ОПЦИИ]

ОПЦИИ:
    -h, --help              Показать эту справку
    -v, --verbose           Подробный вывод (включая hex dump)
    -s, --stats             Показывать только статистику
    -i, --interface IFACE   Указать сетевой интерфейс
    -p, --protocol PROTO    Фильтр по протоколу (tcp/udp/icmp/icmpv6)
    --ip IP                 Фильтр по IP адресу
    --port PORT             Фильтр по номеру порта

ПРИМЕРЫ:
    sudo ./sniffer                           # Захват всех пакетов
    sudo ./sniffer -v                        # С подробным выводом
    sudo ./sniffer -p tcp --port 80          # Только HTTP трафик
    sudo ./sniffer --ip 8.8.8.8             # Пакеты от/к Google DNS

ПРИМЕЧАНИЕ:
    Программа требует root привилегий или CAP_NET_RAW capability.
)";
}
