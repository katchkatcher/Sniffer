#pragma once
#include <cstddef>  // для size_t

namespace sniffer
{
    void hex_dump(const unsigned char *data, size_t size);
}