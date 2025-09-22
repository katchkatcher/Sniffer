#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <net/if_arp.h> // библиотека для байта ether заголовка
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>

// красивый вывод IP адреса
void print_mac(const char *label, unsigned char mac[6])
{
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// вывод TCP флагов
void print_tcp_flags(struct tcphdr *tcp)
{
    printf("TCP Flags: ");
    if (tcp->urg)
        printf("URG ");
    if (tcp->ack)
        printf("ACK ");
    if (tcp->psh)
        printf("PSH ");
    if (tcp->rst)
        printf("RST ");
    if (tcp->syn)
        printf("SYN ");
    if (tcp->fin)
        printf("FIN ");
    printf("\n");
}

// Печать сырых байт пакета в hex + ASCII
// формат строки : <смещение> <16 байт hex> <16 печатных ASCII или ".">
static void hex_dump(const unsigned char *data, int size)
{
    for (int i = 0; i < size; i += 16)
    {
        // смещение
        printf("%04x  ", i);

        // левая колонка: HEX
        for (int j = 0; j < 16; ++j)
        {
            if (i + j < size)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
        }

        printf(" ");

        // правая колонка: ASCII (непечатаемое → '.')
        for (int j = 0; j < 16 && (i + j) < size; ++j)
        {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

void analyze_packet(unsigned char *buffer, int size)
{
    // проверка размера пакета Eth заголовка
    if (size < (int)sizeof(struct ethhdr))
    {
        printf("Слишком маленький пакет: %d байт\n---\n", size);
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)buffer;
    print_mac("MAC отправителя", eth->h_source);
    print_mac("MAC получателя", eth->h_dest);

    // порядок сетевой -> хосотовый
    uint16_t ether_type = ntohs(eth->h_proto);
    printf("EtherType: 0x%04x\n", ether_type);

    // Если это IP пакет и достаточно данных для IP заголовка
    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        // длина ethernet заголовка
        size_t eth_len = sizeof(struct ethhdr);

        if (size < int(eth_len + sizeof(struct iphdr)))
        {
            printf("Пакет усечён: нет полного IP заголовка\n");
            return;
        }

        // сдвигаем указатель на размер ethernet заголовка чтобы попасть на IP заголовок
        // указатель приводим к iphdr
        struct iphdr *ip = (struct iphdr *)(buffer + eth_len);

        // ihl - internet header length - длина ip заголовка
        // 32 бита слово умножаем и получаем всю длинну в байтах
        size_t ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(struct iphdr) || size < (int)(eth_len + ip_hlen))
        {
            // zu нужен для вывода size_t
            printf("Некорректная длина IP заголовка: %zu\n", ip_hlen);
            return;
        }

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        // новый вариант функции преобразования IP в строку, только с поддержкой
        // IPv6 и динамическим буфером
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        // saddr - адрес отправителя
        // daddr - адрес получателя
        // берём ссылку на IP адрес в байтах, затем приводим к типу укзателя на байтовое значение и разыменовываем
        // inet_ntoa нужно для преобразования адреса в строковый вид "x.x.x.x"

        // ещё проще, присваивание полю s_addr (указателю) ссылки на IP в HEX виде
        // это нужно так как inet_ntoa ожидает struct in_addr
        printf("IP(отправитель -> получатель): %s -> %s\n", src_ip, dst_ip);
        printf("IP Protocol: %d, TTL: %d\n", ip->protocol, ip->ttl);

        // если имеем дело с TCP пакетом
        if (ip->protocol == IPPROTO_TCP)
        {
            if (size < (int)(eth_len + ip_hlen + sizeof(struct tcphdr)))
            {
                printf("Пакет усечён: нет полного TCP заголовка\n");
                return;
            }

            struct tcphdr *tcp = (struct tcphdr *)(buffer + eth_len + ip_hlen);
            printf("TCP(отправитель -> получатель): %d -> %d\n", ntohs(tcp->source), ntohs(tcp->dest));

            print_tcp_flags(tcp);
        }
        else if (ip->protocol == IPPROTO_UDP)
        {
            if (size < (int)(eth_len + ip_hlen + sizeof(struct udphdr)))
            {
                printf("Пакет усечён: нет полного UDP заголовка\n");
                return;
            }

            struct udphdr *udp = (struct udphdr *)(buffer + eth_len + ip_hlen);
            printf("UDP(отправитель -> получатель): %d -> %d (len=%d)\n",
                   ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
        }
        else if (ip->protocol == IPPROTO_ICMP)
        {
            printf("ICMP пакет\n");
        }
    }
    else if (ntohs(eth->h_proto) == ETH_P_ARP)
    {
        printf("ARP пакет\n");
    }

    printf("---\n");
}

// флаг остановки программы
volatile sig_atomic_t stop = 0;

// сигнал завершения программы
void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
    printf("\nПолучен сигнал %d, завершаем работу...\n", sig);
}

// красивый заголовок ASCII
void print_header()
{
    FILE *header_file = fopen("docs/header.txt", "r");
    if (header_file == NULL)
    {
        printf("=== Network Packet Analyzer ===\n");
        printf("Заголовочный файл не найден, используем стандартный заголовок\n");
        return;
    }

    // читаем построчно из файла
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), header_file) != NULL)
    {
        printf("%s", buffer);
    }
    fclose(header_file);
    printf("\n");
}

int main()
{
    print_header();

    // установка обработчиков сигналов
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // создание raw socket
    // AF_PACKET/SOCK_RAW/ETH_P_ALL - получаем L2 кадры(включая ethetnet заголовки)
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("Ошибка создания сокета");
        if(errno == EPERM || errno == EACCES)
        {  
            puts("Требуются права root или capability CAP_NET_RAW.\n"
                "Варианты:\n"
                "   sudo ./build/Sniffer\n"
                "   или: sudo setcap cap_net_raw,cap_net_admin+eip ./build/Sniffer");
        }
        return 1;
    }

    printf("Сниффер запущен. Нажмите Ctrl + c для завершения работы.\n\n");

    int packet_count = 0;

    while (!stop)
    {
        unsigned char buffer[65536];

        // метаданные канального уровня(пакеты Ethernet)
        struct sockaddr_ll addr;
        socklen_t addrlen = sizeof(addr);
        // будем фильтровать и получать только данные канального уровня
        int size = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addrlen);

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

        // выводим имя интерфейса и тип пакета
        char ifname[IF_NAMESIZE] = {0};
        if_indextoname(addr.sll_ifindex, ifname);
        printf("iface=%s pkttype=%d protocol=0x%04x\n", ifname, addr.sll_pkttype, ntohs(addr.sll_protocol));

        if (size > 0 && !stop)
        {
            packet_count++;
            printf("Пакет #%d (%d байт):\n", packet_count, size);
            printf("Hex dump:\n");
            hex_dump(buffer, size);
            analyze_packet(buffer, size);
        }
    }

    printf("Корректно закрываем сокет...");
    close(sockfd);
    printf("Обработано пакетов: %d\n", packet_count);

    return 0;
}