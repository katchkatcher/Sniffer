#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

struct CliOptions
{
    std::string interface;
    std::optional<std::string> protocol_filter;
    std::optional<std::string> ip_filter;
    std::optional<uint16_t> port_filter;
    bool verbose = false;
    bool stats_only = false;
};

class CliParser
{
public:
    static CliOptions parse(int argc,const char * const argv[]);
    static void print_help();
};