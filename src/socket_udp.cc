//
//  udp_socket.cc
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
#include "socket_udp.h"


/* udp_datagram_socket */

udp_datagram_socket::udp_datagram_socket()
: bind_addr(), connect_addr()
{
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        log_error("socket(AF_INET, SOCK_DGRAM): %s", strerror(errno));
        return;
    }
    
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        log_error("setsockopt(SOL_SOCKET, SO_REUSEADDR): %s", strerror(errno));
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_error("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_error("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
}

udp_datagram_socket::~udp_datagram_socket()
{
}

bool udp_datagram_socket::setIPV6only(int ipv6only)
{
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, sizeof(ipv6only)) < 0) {
        log_error("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) failed: %s", strerror(errno));
        return false;
    } else {
        return true;
    }
}

bool udp_datagram_socket::bind(socket_addr bind_addr)
{
    socklen_t sa_len = socket_addr::len(bind_addr);
    memcpy(&this->bind_addr, &bind_addr, sa_len);
    if (::bind(fd,(struct sockaddr *)&bind_addr.saddr, sa_len) < 0)
    {
        return false;
    } else {
        return true;
    }
}

bool udp_datagram_socket::connect(socket_addr connect_addr)
{
    socklen_t sa_len = socket_addr::len(connect_addr);
    memcpy(&this->connect_addr, &bind_addr, sa_len);
    if (::connect(fd,(struct sockaddr *)&connect_addr.saddr, sa_len) < 0)
    {
        return false;
    } else {
        return true;
    }
}

io_result udp_datagram_socket::sendto(const void *buffer, size_t len, const socket_addr &dest_addr)
{
    socklen_t sa_len = socket_addr::len(dest_addr);
    ssize_t ret = ::sendto(fd, buffer, len, 0, &dest_addr.saddr, sa_len);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result udp_datagram_socket::send(const void *buffer, size_t len)
{
    ssize_t ret = ::send(fd, buffer, len, 0);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result udp_datagram_socket::recvfrom(void *buffer, size_t len, socket_addr &src_addr)
{
    socklen_t address_len = sizeof(src_addr);
    ssize_t ret = ::recvfrom(fd, buffer, len, 0, &src_addr.saddr, &address_len);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result udp_datagram_socket::recv(void *buffer, size_t len)
{
    ssize_t ret = ::recv(fd, buffer, len, 0);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}


/* multicast_udp_datagram_socket */

multicast_udp_datagram_socket::multicast_udp_datagram_socket()
: iface_addr(), mcast_group_list()
{
}

multicast_udp_datagram_socket::~multicast_udp_datagram_socket()
{
    for (auto mcast_addr : mcast_group_list) {
        leave_multicast_group(mcast_addr);
    }
}

bool multicast_udp_datagram_socket::set_multicast_iface(const socket_addr &iface_addr)
{
    if (iface_addr.saddr.sa_family == AF_INET) {
        memcpy(&this->iface_addr, &iface_addr, sizeof(sockaddr_in));
        if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &iface_addr.ip4addr.sin_addr, sizeof(struct in_addr)) < 0) {
            log_error("set_multicast_iface: setsockopt(IPPROTO_IP, IP_MULTICAST_IF): %s", strerror(errno));
        }
    } else if (iface_addr.saddr.sa_family == AF_INET6) {
        setIPV6only(true);
        memcpy(&this->iface_addr, &iface_addr, sizeof(sockaddr_in6));
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface_addr.ip6addr.sin6_addr, sizeof(struct in6_addr)) < 0) {
            log_error("set_multicast_iface: setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_IF): %s", strerror(errno));
        }
    } else {
        log_error("set_multicast_iface: unknown address family: %d", iface_addr.saddr.sa_family);
        return false;
    }
    
    return true;
}

bool multicast_udp_datagram_socket::set_multicast_loop(unsigned char loop)
{
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        log_error("set_multicast_loop: setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP): %s", strerror(errno));
        return false;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        log_error("set_multicast_loop: setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP): %s", strerror(errno));
        return false;
    }
    
    return true;
}

bool multicast_udp_datagram_socket::set_multicast_ttl(unsigned char ttl)
{
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        log_error("set_multicast_ttl: setsockopt(IPPROTO_IP, IP_MULTICAST_TTL): %s", strerror(errno));
        return false;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
        log_error("set_multicast_ttl: setsockopt(IPPROTO_IP, IPV6_MULTICAST_HOPS): %s", strerror(errno));
        return false;
    }
    
    return true;
}

bool multicast_udp_datagram_socket::join_multicast_group(const socket_addr &mcast_addr)
{
    if (iface_addr.saddr.sa_family == AF_INET) {
        struct ip_mreq mreq;
        memcpy(&mreq.imr_interface, &iface_addr.ip4addr.sin_addr, sizeof(struct in_addr));
        memcpy(&mreq.imr_multiaddr, &mcast_addr.ip4addr.sin_addr, sizeof(struct in_addr));
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            log_error("join_multicast_group: setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
        }
    } else if (iface_addr.saddr.sa_family == AF_INET6) {
        struct ipv6_mreq mreq6;
        memcpy(&mreq6.ipv6mr_interface, &iface_addr.ip6addr.sin6_addr, sizeof(struct in6_addr));
        memcpy(&mreq6.ipv6mr_multiaddr, &mcast_addr.ip6addr.sin6_addr, sizeof(struct in6_addr));
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) < 0) {
            log_error("join_multicast_group: setsockopt(IPV6_JOIN_GROUP): %s", strerror(errno));
        }
    } else {
        log_error("join_multicast_group: unknown address family: %d", iface_addr.saddr.sa_family);
        return false;
    }
    mcast_group_list.push_back(mcast_addr);
    
    return true;
}

bool multicast_udp_datagram_socket::leave_multicast_group(const socket_addr &mcast_addr)
{
    if (mcast_addr.saddr.sa_family == AF_INET) {
        struct ip_mreq mreq;
        memcpy(&mreq.imr_interface, &iface_addr.ip4addr.sin_addr, sizeof(struct in_addr));
        memcpy(&mreq.imr_multiaddr, &mcast_addr.ip4addr.sin_addr, sizeof(struct in_addr));
        if (setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            log_error("leave_multicast_group: setsockopt(IP_DROP_MEMBERSHIP): %s", strerror(errno));
        }
    } else if (mcast_addr.saddr.sa_family == AF_INET6) {
        struct ipv6_mreq mreq6;
        memcpy(&mreq6.ipv6mr_interface, &iface_addr.ip6addr.sin6_addr, sizeof(struct in6_addr));
        memcpy(&mreq6.ipv6mr_multiaddr, &mcast_addr.ip6addr.sin6_addr, sizeof(struct in6_addr));
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq6, sizeof(mreq6)) < 0) {
            log_error("leave_multicast_group: setsockopt(IPV6_LEAVE_GROUP): %s", strerror(errno));
        }
    } else {
        log_error("leave_multicast_group: unknown address family: %d", mcast_addr.saddr.sa_family);
        return false;
    }
    
    return true;
}
