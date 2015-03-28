//
//  resolver.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cstring>
#include <cassert>
#include <memory>
#include <deque>
#include <sstream>
#include <string>
#include <vector>

#include "log.h"
#include "io.h"
#include "socket.h"
#include "resolver.h"

/* resolver */

bool resolver::lookup(socket_addr &addr, std::string host, int port)
{
    memset(&addr, 0, sizeof(addr));
    addr.saddr.sa_family = AF_INET;
    addr.ip4addr.sin_port = htons(port);
    
    // parse host:port
    if (port == 0) {
        size_t host_colon_pos = host.find_last_of(':');
        if (host_colon_pos != std::string::npos) {
            port = atoi(host.substr(host_colon_pos + 1).c_str());
            host = host.substr(0, host_colon_pos);
        }
    }
    
    // gethostbyname on BSD uses thread local storage
    // TODO - use getaddrinfo or gethostbyname_r (on linux)
    struct hostent *he = gethostbyname(host.c_str());
    if (he) {
        if (he->h_addrtype == AF_INET) {
            addr.ip4addr.sin_port = htons(port);
            memcpy(&addr.ip4addr.sin_addr, he->h_addr_list[0], he->h_length);
        } else if (he->h_addrtype == AF_INET6) {
            addr.ip6addr.sin6_port = htons(port);
            memcpy(&addr.ip6addr.sin6_addr, he->h_addr_list[0], he->h_length);
        } else {
            memset(&addr.ip4addr.sin_addr, 0, sizeof(addr.ip4addr.sin_addr));
            log_error("resolver::lookup: %s: unknown address type: %s", host.c_str(), he->h_addrtype);
            return false;
        }
    } else {
        memset(&addr.ip4addr.sin_addr, 0, sizeof(addr.ip4addr.sin_addr));
        log_error("resolver::lookup: %s: %s", host.c_str(), hstrerror(h_errno));
        return false;
    }
    
    return true;
}
