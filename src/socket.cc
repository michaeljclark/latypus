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


#if defined(TCP_CORK) && !defined(TCP_NOPUSH)
#define TCP_NOPUSH TCP_CORK
#endif

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


/* socket_addr */

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



/* unix_socketpair */

unix_socketpair::unix_socketpair(int buf_size)
{
    int fdvec[2];
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fdvec) < 0) {
		log_fatal_exit("socket failed: %s", strerror(errno));
    }
    owner.set_fd(fdvec[0]);
    client.set_fd(fdvec[1]);
    
    if (setsockopt(owner.fd, SOL_SOCKET, SO_RCVBUF, (void *)&buf_size, sizeof(buf_size)) < 0) {
		log_fatal_exit("setsockopt(SO_RCVBUF) failed: %s", strerror(errno));
    }
    if (setsockopt(client.fd, SOL_SOCKET, SO_RCVBUF, (void *)&buf_size, sizeof(buf_size)) < 0) {
		log_fatal_exit("setsockopt(SO_RCVBUF) failed: %s", strerror(errno));
    }

	if (fcntl(owner.fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
	if (fcntl(owner.fd, F_SETFL, O_NONBLOCK) < 0) {
		log_error("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
	if (fcntl(client.fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
	if (fcntl(client.fd, F_SETFL, O_NONBLOCK) < 0) {
		log_error("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
}

io_result unix_socketpair::send_message(unix_socketpair_user user, void *buffer, size_t length)
{
    struct iovec iv[1];
    memset(iv, 0, sizeof(iv));
    iv[0].iov_base = buffer;
    iv[0].iov_len = length;
    
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = iv;
    mh.msg_iovlen = 1;
    
    ssize_t ret;
    int fd = (user == unix_socketpair_owner) ? owner.get_fd() : client.get_fd();
    if ((ret = sendmsg(fd, &mh, 0)) < 0) {
        return io_result(io_error(errno));
    }
    return io_result(ret);
}

io_result unix_socketpair::recv_message(unix_socketpair_user user, void *buffer, size_t length)
{
    struct iovec iv[1];
    memset(iv, 0, sizeof(iv));
    iv[0].iov_base = buffer;
    iv[0].iov_len = length;
    
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = iv;
    mh.msg_iovlen = 1;
    
    ssize_t ret;
    int fd = (user == unix_socketpair_owner) ? owner.get_fd() : client.get_fd();
    if ((ret = recvmsg(fd, &mh, 0)) < 0) {
        return io_result(io_error(errno));
    }
    return io_result(ret);
}


/* listening_socket */

listening_socket::listening_socket(socket_addr addr, int backlog) : addr(addr), backlog(backlog) {}

bool listening_socket::start_listening()
{
    fd = socket(addr.saddr.sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("socket failed: %s", strerror(errno));
        return false;
    }
    if (addr.saddr.sa_family == AF_INET6) {
        int ipv6only = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, sizeof(ipv6only)) < 0) {
            log_error("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) failed: %s", strerror(errno));
            return false;
        }
    }
    int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) < 0) {
		log_error("setsockopt(SOL_SOCKET, SO_REUSEADDR) failed: %s", strerror(errno));
        return false;
    }
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
        return false;
    }
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		log_error("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
        return false;
    }
    
    socklen_t addr_size = 0;
    if (addr.saddr.sa_family == AF_INET) addr_size = sizeof(addr.ip4addr);
    if (addr.saddr.sa_family == AF_INET6) addr_size = sizeof(addr.ip6addr);
	if (bind(fd, (struct sockaddr *) &addr.storage, addr_size) < 0) {
		log_error("bind failed: %s: %s", to_string().c_str(), strerror(errno));
        return false;
    }
	if (listen(fd, (int)backlog) < 0) {
		log_error("listen failed: %s", strerror(errno));
        return false;
    }
    
    return true;
}

std::string listening_socket::to_string()
{
    return socket_addr::addr_to_string(addr);
}


/* connected_socket */

connected_socket::connected_socket() : generic_socket(-1), lingering_close(0), nopush(0), nodelay(0) {}

connected_socket::connected_socket(int fd) : generic_socket(fd), lingering_close(0), nopush(0), nodelay(0)
{
    if (fd < 0) return;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("fcntl(%d, F_SETFD, FD_CLOEXEC) failed: %s", fd, strerror(errno));
    }
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		log_error("fcntl(%d, F_SETFL, O_NONBLOCK) failed: %s", fd, strerror(errno));
    }
}

bool connected_socket::connect_to_host(socket_addr addr)
{
    set_fd(-1);
    
    fd = socket(addr.saddr.sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("socket failed: %s", strerror(errno));
        return false;
    }
    if (addr.saddr.sa_family == AF_INET6) {
        int ipv6only = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, sizeof(ipv6only)) < 0) {
            log_error("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) failed: %s", strerror(errno));
        }
    }
    int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) < 0) {
		log_error("setsockopt(SOL_SOCKET, SO_REUSEADDR) failed: %s", strerror(errno));
    }
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
		log_error("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		log_error("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
    int ret = connect(fd, (struct sockaddr *) &addr.storage, socket_addr::len(addr));
    if (ret < 0 && errno != EINPROGRESS) {
		log_error("connect failed: %s", strerror(errno));
        return false;
    }
    return true;
}

bool connected_socket::set_nopush(bool nopush)
{
    unsigned int val = nopush ? 1 : 0;
    if (this->nopush == val) return true;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val)) < 0) {
		log_error("setsockopt(TCP_NOPUSH) failed: %s", strerror(errno));
        return false;
    } else {
        this->nopush = val;
        return true;
    }
}

bool connected_socket::set_nodelay(bool nodelay)
{
    unsigned int val = nodelay ? 1 : 0;
    if (this->nodelay == val) return true;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0) {
		log_error("setsockopt(TCP_NODELAY) failed: %s", strerror(errno));
        return false;
    } else {
        this->nodelay = val;
        return true;
    }
}

bool connected_socket::start_lingering_close()
{
    /* called in the case of a server initiated close (half-close).
     * i.e. timeouts of keepalive connections and aborts */
    if (lingering_close) return true;
    if (shutdown(fd, SHUT_WR) < 0) {
		log_debug("shutdown failed: %s", strerror(errno));
        close(fd);
        return false;
    } else {
        lingering_close = true;
        return true;
    }
}

io_result connected_socket::read(void *buf, size_t len)
{
    ssize_t nbytes;
    do {
        nbytes = ::read(fd, buf, len);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result connected_socket::readv(const struct iovec *iov, int iovcnt)
{
    ssize_t nbytes;
    do {
        nbytes = ::readv(fd, iov, iovcnt);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result connected_socket::write(void *buf, size_t len)
{
    ssize_t nbytes;
    do {
        nbytes = ::write(fd, buf, len);
    } while (nbytes < 0 && errno == EAGAIN);

    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result connected_socket::writev(const struct iovec *iov, int iovcnt)
{
    ssize_t nbytes;
    do {
        nbytes = ::writev(fd, iov, iovcnt);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}


/* datagram_socket */

datagram_socket::datagram_socket()
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

datagram_socket::~datagram_socket()
{
}

bool datagram_socket::setIPV6only(int ipv6only)
{
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, sizeof(ipv6only)) < 0) {
        log_error("setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) failed: %s", strerror(errno));
        return false;
    } else {
        return true;
    }
}

bool datagram_socket::bind(socket_addr bind_addr)
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

bool datagram_socket::connect(socket_addr connect_addr)
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

io_result datagram_socket::sendto(const void *buffer, size_t len, const socket_addr &dest_addr)
{
    socklen_t sa_len = socket_addr::len(dest_addr);
    ssize_t ret = ::sendto(fd, buffer, len, 0, &dest_addr.saddr, sa_len);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result datagram_socket::send(const void *buffer, size_t len)
{
    ssize_t ret = ::send(fd, buffer, len, 0);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result datagram_socket::recvfrom(void *buffer, size_t len, socket_addr &src_addr)
{
    socklen_t address_len = sizeof(src_addr);
    ssize_t ret = ::recvfrom(fd, buffer, len, 0, &src_addr.saddr, &address_len);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}

io_result datagram_socket::recv(void *buffer, size_t len)
{
    ssize_t ret = ::recv(fd, buffer, len, 0);
    return (ret < 0) ? io_result(io_error(errno)) : io_result(ret);
}


/* multicast_datagram_socket */

multicast_datagram_socket::multicast_datagram_socket()
    : iface_addr(), mcast_group_list()
{
}

multicast_datagram_socket::~multicast_datagram_socket()
{
    for (auto mcast_addr : mcast_group_list) {
        leave_multicast_group(mcast_addr);
    }
}

bool multicast_datagram_socket::set_multicast_iface(const socket_addr &iface_addr)
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

bool multicast_datagram_socket::set_multicast_loop(unsigned char loop)
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

bool multicast_datagram_socket::set_multicast_ttl(unsigned char ttl)
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

bool multicast_datagram_socket::join_multicast_group(const socket_addr &mcast_addr)
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

bool multicast_datagram_socket::leave_multicast_group(const socket_addr &mcast_addr)
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

