# Sniffer — легковесный анализатор сетевых пакетов для Linux

Небольшой, быстрый и понятный сниффер для Linux, написанный на C++17. Работает напрямую с AF_PACKET/RAW сокетом (L2), умеет красиво печатать заголовки, фильтровать по протоколу/IP/порту и выводить hexdump полезной нагрузки.


## Возможности

- Захват кадров уровня L2 через AF_PACKET (SOCK_RAW, ETH_P_ALL)
- Разбор и учёт:
	- IPv4 (IHL, фрагментация; для фрагментов offset>0 L4 не парсится)
	- IPv6 (базовый заголовок + пропуск цепочки extension headers до L4)
	- TCP, UDP, ICMP (v4) и ICMPv6
	- ARP
	- VLAN 802.1Q/802.1AD (одиночный тег)
- Фильтры захвата и вывода:
	- по протоколу: tcp / udp / icmp / icmpv6
	- по IP-адресу (IPv4 или IPv6; src или dst)
	- по порту (TCP/UDP; src или dst)
	- по интерфейсу (bind к конкретному ifname, включая loopback `lo`)
- Режимы:
	- verbose: подробный вывод + hexdump
	- stats-only: только агрегированная статистика
- Цветной вывод с авто-детектом TTY (FORCE_COLOR / NO_COLOR)
- Корректное завершение по Ctrl+C без зависания (SO_RCVTIMEO)
- Минимальные зависимости, CMake + CTest


## Требования и поддерживаемая платформа

- Linux (используются заголовки Linux и AF_PACKET)
- Компилятор C++17 (g++/clang++)
- CMake >= 3.20
- Для запуска требуется root или capability CAP_NET_RAW (+рекомендовано CAP_NET_ADMIN) для работы RAW сокетов

Опционально для разработки:
- cppcheck, clang-tidy (статический анализ)
- gdb (отладка)


## Установка и сборка

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build -j
```

Сборка в Debug с AddressSanitizer:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build -j
```


## Запуск

Снифферу нужны права для открытия RAW сокета. Варианты:

- Запустить под root:

```bash
sudo ./build/Sniffer
```

- Или выдать бинарнику capability (рекомендуется для повседневной работы):

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./build/Sniffer
./build/Sniffer
```

Привязка к интерфейсу (пример: wlan0) и подробный вывод:

```bash
sudo ./build/Sniffer -i wlan0 -v
```

Фильтрация только TCP на порту 80 (HTTP):

```bash
sudo ./build/Sniffer -p tcp --port 80
```

Показать только статистику (без «шума»):

```bash
sudo ./build/Sniffer -s
```


## CLI-опции

- `-h, --help` — показать справку
- `-v, --verbose` — подробный вывод (включая hexdump)
- `-s, --stats` — печатать только сводную статистику по завершении
- `-i, --interface IFACE` — привязать сокет к интерфейсу (например, `eth0`, `wlan0`)
- `-p, --protocol PROTO` — фильтр по протоколу (`tcp` / `udp` / `icmp` / `icmpv6`)
- `--ip IP` — фильтр по IP-адресу источника или назначения
- `--port PORT` — фильтр по номеру порта источника или назначения (TCP/UDP)

Примеры:

```bash
sudo ./build/Sniffer                           # Захват всех пакетов
sudo ./build/Sniffer -v                        # Подробный вывод + hexdump
sudo ./build/Sniffer -i wlan0 -p udp            # Только UDP на интерфейсе wlan0
sudo ./build/Sniffer -p tcp --port 443         # TLS/HTTPS трафик
sudo ./build/Sniffer --ip 8.8.8.8              # Пакеты от/к Google DNS
sudo ./build/Sniffer -s                        # Только статистика
```


## Пример вывода

Краткий режим (не verbose):

```
TCP 192.168.1.10:55234 -> 142.250.150.36:443 TTL=63 IHL=20
UDP 192.168.1.10:5353  -> 224.0.0.251:5353  TTL=255 IHL=20 LEN=68
ICMP 192.168.1.10 -> 1.1.1.1 type=8 code=0 TTL=58 IHL=20
TCP  ::1:443 -> ::1:57544 (IPv6)
ICMPv6 ::1 -> ::1 type=128 code=0
=== СТАТИСТИКА ПАКЕТОВ ===
Всего пакетов: 129
IPv4 пакетов:  110
IPv6 пакетов:  6
TCP пакетов:   84
UDP пакетов:   25
ICMP пакетов:  5
ICMPv6 пакетов:2
ARP пакетов:   8
Прочие пакеты: 1
Общий объём:   152400 байт
```

Verbose-режим дополнительно печатает адреса L2, флаги TCP, подробности ICMP и hexdump полезной нагрузки (с цветом, если вывод в TTY).


## Цвета вывода

- Автоматически включаются только при выводе в TTY
- Переменные окружения:
	- `FORCE_COLOR=1` — принудительно включить цвета
	- `NO_COLOR=1` — принудительно отключить цвета


## Тесты

Сборка тестов включается флагом `-DBUILD_TESTING=ON` (по умолчанию в примере выше он включён). Запуск:

```bash
ctest --test-dir build --output-on-failure
```

В составе есть базовые unit-тесты для CLI-парсера, форматтера и анализатора пакетов (минимальные кейсы на корректность и граничные условия).


## Статический анализ

```bash
cppcheck --enable=warning,style,performance,portability --std=c++17 --inline-suppr \
	--suppress=missingIncludeSystem -I include -I src --force .

run-clang-tidy -p build
```
## Структура репозитория (основное)

```
include/              # Заголовочные файлы (API)
src/                  # Реализация
tests/                # Юнит-тесты (CTest)
docs/header.txt       # ASCII-заголовок для красивого старта
CMakeLists.txt        # Сборка
build/                # Артефакты сборки (вне git)
```


## Ограничения и заметки по реализации

- IPv6: extension headers только пропускаются (не детализируются; ESP/AH не анализируются)
- Разбор VLAN — один тег (nested/q-in-q частично не поддержан)
- Фрагментированные IPv4 (offset>0) и IPv6 (если fragment header внутри цепочки) — L4 нагрузка не разбирается
- Нет записи pcap/pcapng и BPF/eBPF фильтрации (осознанно для минимализма)
- Нет декодирования ICMP/ICMPv6 типов глубже базовых полей (можно расширить)


## Roadmap (идеи для развития)

- Декодирование конкретных IPv6 extension headers (Routing, Fragment details)
- Парсинг ICMP/ICMPv6 типов (Echo, ND, Time Exceeded, Router/Neighbor Discovery)
- Pcap/pcapng запись и офлайн-парсинг
- BPF / eBPF фильтрация или интеграция с libpcap
- Промискуитетный режим и множественные интерфейсы одновременно
- Простая сигнатурная идентификация приложений (порт/протокол эвристики)
- Расширенная статистика (частоты портов, распределение TTL/Hop Limit)
- Экспорт метрик (Prometheus / JSON)

## Лицензия

MIT — см. файл `LICENSE`.


## Дополнительные примечания

- Проект задуман как образовательный и утилитарный инструмент для быстрого анализа трафика в Linux
- В заголовке при старте используется `docs/header.txt` (fallback при отсутствии)
- Поддерживается loopback (`-i lo`) — можно тестировать `ping -6 ::1`
- Корректное завершение по Ctrl+C обеспечивается таймаутом чтения сокета (SO_RCVTIMEO)

