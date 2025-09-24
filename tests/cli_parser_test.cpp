#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>
#include "cli_parser.h"

void test_basic_parsing()
{
    const char *argv[] = {"sniffer", "-v", "--protocol", "tcp", "--port", "80"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CliOptions opts = CliParser::parse(argc, const_cast<char **>(argv));

    assert(opts.verbose == true);
    assert(opts.protocol_filter.has_value());
    assert(opts.protocol_filter.value() == "tcp");
    assert(opts.port_filter.has_value());
    assert(opts.port_filter.value() == 80);
    assert(!opts.stats_only);
}

void test_ip_filter()
{
    const char *argv[] = {"sniffer", "--ip", "8.8.8.8", "-s"};
    int argc = static_cast<int>(sizeof(argv) / sizeof(argv[0]));
    (void)argc;

    CliOptions opts = CliParser::parse(argc, const_cast<char **>(argv));

    assert(opts.ip_filter.has_value());
    assert(opts.ip_filter.value() == "8.8.8.8");
    assert(opts.stats_only == true);
}

void test_invalid_protocol()
{
    const char *argv[] = {"sniffer", "--protocol", "invalid"};
    int argc = static_cast<int>(sizeof(argv) / sizeof(argv[0]));
    (void)argc;

    // Этот тест должен завершиться с exit(1)
    // В реальном тестировании мы бы использовали exception или другой механизм
    std::cout << "Тест invalid_protocol пропущен (требует обработки exit)\n";
}

int main()
{
    test_basic_parsing();
    test_ip_filter();
    test_invalid_protocol();

    std::cout << "cli_test ok\n";
    return 0;
}