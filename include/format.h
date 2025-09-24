#pragma once

#include <cstdio>  // snprintf
#include <cstdlib> // getenv
#include <cstdint>
#include <unistd.h>     // isatty
#include <netinet/in.h> // IPPROTO и иные константы

namespace Format
{
    inline bool colors_enabled()
    {
        // проверка на запрет цвета(в переменных окружения)
        const char *force = std::getenv("FORCE_COLOR");
        const char *no_color = std::getenv("NO_COLOR");

        if (force && *force != '0')
            return true;
        if (no_color && *no_color != '0')
            return false;

        // проверка на то что вывод в терминале а не в файле
        return isatty(STDOUT_FILENO) == 1;
    }

    // функция сброса цвета
    inline const char *reset()
    {
        // constexpr - посчитаем во время компиляции
        // \033[0m - сбрасывает все атрибуты текста
        static constexpr const char *ESC_RESET = "\033[0m";
        return colors_enabled() ? ESC_RESET : "";
    }
    inline const char *green()
    {
        // \033[32m - зелёный(ANSII код)
        static constexpr const char *ESC_GREEN = "\033[32m";
        return colors_enabled() ? ESC_GREEN : "";
    }
    inline const char *blue()
    {
        // \033[34m - голубой(ANSII код)
        static constexpr const char *ESC_BLUE = "\033[34m";
        return colors_enabled() ? ESC_BLUE : "";
    }
    inline const char *yellow()
    {
        // \033[33m - жёлтый(ANSII код)
        static constexpr const char *ESC_YELLOW = "\033[33m";
        return colors_enabled() ? ESC_YELLOW : "";
    }
    inline const char *magenta()
    {
        // \033[35m - пурпурный(ANSII код)
        static constexpr const char *ESC_MAGENTA = "\033[35m";
        return colors_enabled() ? ESC_MAGENTA : "";
    }

    inline const char *bold()
    {
        static constexpr const char *ESC_BOLD = "\033[1m";
        return colors_enabled() ? ESC_BOLD : "";
    }

    inline const char *dim()
    {
        static constexpr const char *ESC_DIM = "\033[2m";
        return colors_enabled() ? ESC_DIM : "";
    }

    inline const char *l4_name(uint8_t proto)
    {
        switch (proto)
        {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
        {
            // для неизвестных протоколов будет локальный буфер
            static thread_local char buf[16];
            // гарантирует отсутствие переполнения буфера
            std::snprintf(buf, sizeof(buf), "PROTO-%u", proto);
            return buf;
        }
        }
    }
    inline const char *l4_color(uint8_t proto)
    {
        switch (proto)
        {
        case IPPROTO_TCP:
            return green();
        case IPPROTO_UDP:
            return blue();
        case IPPROTO_ICMP:
            return yellow();
        default:
            return "";
        }
    }
} // namespace Format
