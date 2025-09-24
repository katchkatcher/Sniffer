#include <cassert>
#include <cstring>
#include <netinet/in.h>
#include "format.h"

int main()
{
    using namespace Format;
    // assert проверка истинности условия
    assert(std::strcmp(l4_name(IPPROTO_TCP), "TCP") == 0);
    assert(std::strcmp(l4_name(IPPROTO_UDP), "UDP") == 0);
    assert(std::strcmp(l4_name(IPPROTO_ICMP), "ICMP") == 0);

    const char*other = l4_name(99);
    assert(std::strncmp(other, "PROTO-", 6) == 0);
    (void)other;

    puts("protocol_forman_test ok");
    return 0;
}