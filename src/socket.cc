//
//  socket.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cassert>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "log.h"
#include "io.h"
#include "socket.h"


/* socket_addr */

socklen_t socket_addr::len(const socket_addr &addr)
{
    socklen_t sa_len;
    switch (addr.saddr.sa_family) {
        case AF_INET: sa_len = sizeof(sockaddr_in); break;
        case AF_INET6: sa_len = sizeof(sockaddr_in6); break;
        case AF_LOCAL: sa_len = sizeof(sockaddr_un); break;
        default: sa_len = sizeof(sockaddr_storage); break;
    }
    return sa_len;
}

std::string socket_addr::addr_to_string(const socket_addr &addr)
{
    std::stringstream ss;
    char buf[256];
    if (addr.saddr.sa_family == AF_INET) {
        ss << inet_ntop(addr.saddr.sa_family, (void*)&addr.ip4addr.sin_addr, buf, sizeof(buf))
           << ":" <<  ntohs(addr.ip6addr.sin6_port);
    }
    if (addr.saddr.sa_family == AF_INET6) {
        ss << "[" << inet_ntop(addr.saddr.sa_family, (void*)&addr.ip6addr.sin6_addr, buf, sizeof(buf)) << "]"
           << ":" <<  ntohs(addr.ip4addr.sin_port);
    }
    return ss.str();
}

int socket_addr::string_to_addr(std::string addr_spec, socket_addr &addr)
{
    size_t open_bracket = addr_spec.find_last_of("[");
    size_t close_bracket = addr_spec.find_last_of("]");
    size_t last_colon = addr_spec.find_last_of(":");
    if ((open_bracket != std::string::npos && close_bracket == std::string::npos) ||
        (open_bracket == std::string::npos && close_bracket != std::string::npos))
    {
        log_error("malformed addr spec: unbalanced brackets []: %s", addr_spec.c_str());
        return -1;
    } else if (open_bracket != std::string::npos && close_bracket != std::string::npos) {
        if (open_bracket != 0 || close_bracket < 1 || last_colon == std::string::npos || last_colon != close_bracket + 1)
        {
            log_error("malformed addr spec: invalid ipv6 format: %s", addr_spec.c_str());
            return -1;
        }
        addr.saddr.sa_family = AF_INET6;
    } else {
        addr.saddr.sa_family = AF_INET;
    }
    
    int port = 0;
    std::string address_part;
    if (last_colon == std::string::npos) {
        port = atoi(addr_spec.c_str());
    } else {
        address_part = (addr.saddr.sa_family == AF_INET6)
            ? addr_spec.substr(open_bracket + 1, close_bracket - open_bracket - 1).c_str()
            : addr_spec.substr(0, last_colon).c_str();
        port = atoi(addr_spec.substr(last_colon + 1).c_str());
    }
    if (port <= 0) {
        log_error("malformed listener spec: port must be non zero: %s", addr_spec.c_str());
        return -1;
    }
    
    if (addr.saddr.sa_family == AF_INET6) {
        addr.ip6addr.sin6_port = htons(port);
        if (address_part.length() == 0) {
            memset(&addr.ip6addr.sin6_addr, 0, sizeof(addr.ip6addr.sin6_addr));
        } else if (!inet_pton(AF_INET6, address_part.c_str(), &addr.ip6addr.sin6_addr)) {
            log_error("inet_pton(AF_INET6, \"%s\"): %s", address_part.c_str(), strerror(errno));
            return -1;
        }
    } else {
        addr.ip4addr.sin_port = htons(port);
        if (address_part.length() == 0) {
            memset(&addr.ip4addr.sin_addr, 0, sizeof(addr.ip4addr.sin_addr));
        } else if (!inet_pton(AF_INET, address_part.c_str(), &addr.ip4addr.sin_addr)) {
            log_error("inet_pton(AF_INET, \"%s\"): %s", address_part.c_str(), strerror(errno));
            return -1;
        }
    }
    
    return 0;
}


/* generic_socket */

generic_socket::generic_socket() : fd(-1) {}

generic_socket::generic_socket(int fd) : fd(fd) {}

generic_socket::~generic_socket()
{
    close_connection();
}

void generic_socket::close_connection()
{
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

void generic_socket::set_fd(int fd)
{
    if (fd != this->fd) {
        if (this->fd >= 0) {
            close(this->fd);
        }
        this->fd = fd;
    }
}

int generic_socket::get_fd() { return fd; }

int generic_socket::get_error()
{
    int error = 0;
    socklen_t error_size = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&error, &error_size) < 0) {
        log_error("getsockopt: SO_ERROR: %s\n", strerror(errno));
    }
    return error;
}


/* connected_socket */

connected_socket::connected_socket() : generic_socket(-1) {}
connected_socket::connected_socket(int fd) : generic_socket(fd) {}
connected_socket::~connected_socket() {}

