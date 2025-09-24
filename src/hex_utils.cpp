#include "hex_utils.h"
#include "format.h"
#include <iostream>
#include <iomanip>
#include <cctype>

namespace sniffer
{
    // Печать сырых байт пакета в hex + ASCII
    // формат строки : <смещение> <16 байт hex> <16 печатных ASCII или ".">
    void hex_dump(const unsigned char *data, size_t size)
    {
        if (!data || size <= 0)
            return;
            
        const size_t bytes_per_line = 16;

        for (size_t i = 0; i < size; i += bytes_per_line)
        {
            // смещение
            // setfill - заполнение
            // setw - смещение
            // std::hex вывод в hex
            std::cout << Format::yellow() << std::setfill('0') << std::setw(4)
                      << std::hex << i << Format::reset() << "  ";

            // левая колонка: HEX
            for (size_t j = 0; j < bytes_per_line; ++j)
            {
                if (i + j < size)
                    std::cout << std::setfill('0') << std::setw(2)
                              << std::hex << static_cast<int>(data[i + j]) << " ";
                else
                    std::cout << "   ";
            }

            std::cout << " ";

            // правая колонка: ASCII (непечатаемое → '.')
            for (size_t j = 0; j < bytes_per_line && (i + j) < size; ++j)
            {
                unsigned char c = data[i + j];
                if (std::isprint(c))
                {
                    std::cout << static_cast<char>(c);
                }
                else
                {
                    std::cout << Format::magenta() << "." << Format::reset();
                }
            }
            std::cout << "\n";
        }
        // возврат десятичного порядка
        std::cout << std::dec;
    }

} // namespace sniffer
