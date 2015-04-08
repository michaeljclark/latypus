//
//  socket_tcp.cc
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
#include "socket_tcp.h"

#if defined(TCP_CORK) && !defined(TCP_NOPUSH)
#define TCP_NOPUSH TCP_CORK
#endif


/* tcp_connected_socket */

tcp_connected_socket::tcp_connected_socket()
    : connected_socket(-1), addr(), backlog(0), lingering_close(0), nopush(0), nodelay(0) {}

tcp_connected_socket::tcp_connected_socket(int fd)
    : connected_socket(fd), addr(), backlog(0), lingering_close(0), nopush(0), nodelay(0)
{
    if (fd < 0) return;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_error("fcntl(%d, F_SETFD, FD_CLOEXEC) failed: %s", fd, strerror(errno));
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_error("fcntl(%d, F_SETFL, O_NONBLOCK) failed: %s", fd, strerror(errno));
    }
}

tcp_connected_socket::~tcp_connected_socket()
{
}

void tcp_connected_socket::set_context(void *context)
{
    // no op - used to set tls context
}

socket_mode tcp_connected_socket::get_mode()
{
    return socket_mode_plain;
}

int tcp_connected_socket::do_handshake()
{
    return 0;
}

bool tcp_connected_socket::start_listening(socket_addr addr, int backlog)
{
    int fd = socket(addr.saddr.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return false;
    }

    set_fd(fd);
    this->addr = addr;
    this->backlog = backlog;
    
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

socket_addr tcp_connected_socket::get_addr()
{
    return addr;
}

std::string tcp_connected_socket::to_string()
{
    return socket_addr::addr_to_string(addr);
}

bool tcp_connected_socket::accept(int fd)
{
    set_fd(fd);
    return true;
}

bool tcp_connected_socket::connect_to_host(socket_addr addr)
{
    int fd = socket(addr.saddr.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("socket failed: %s", strerror(errno));
        return false;
    }
    set_fd(fd);
    
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

bool tcp_connected_socket::set_nopush(bool nopush)
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

bool tcp_connected_socket::set_nodelay(bool nodelay)
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

bool tcp_connected_socket::start_lingering_close()
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

io_result tcp_connected_socket::read(void *buf, size_t len)
{
    ssize_t nbytes;
    do {
        nbytes = ::read(fd, buf, len);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result tcp_connected_socket::readv(const struct iovec *iov, int iovcnt)
{
    ssize_t nbytes;
    do {
        nbytes = ::readv(fd, iov, iovcnt);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result tcp_connected_socket::write(void *buf, size_t len)
{
    ssize_t nbytes;
    do {
        nbytes = ::write(fd, buf, len);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

io_result tcp_connected_socket::writev(const struct iovec *iov, int iovcnt)
{
    ssize_t nbytes;
    do {
        nbytes = ::writev(fd, iov, iovcnt);
    } while (nbytes < 0 && errno == EAGAIN);
    
    return nbytes < 0 ? io_result(io_error(errno)) : io_result(nbytes);
}

