//
//  connection.cc
//

#include "plat_os.h"
#include "plat_net.h"
#include "plat_poll.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <iostream>
#include <sstream>
#include <functional>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <map>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "socket_tcp.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "pollset_poll.h"
#include "pollset_kqueue.h"
#include "protocol.h"
#include "connection.h"


/* connection */

connection::connection() : conn_id(-1), last_activity(0), local_addr(), peer_addr(), nopush(0), nodelay(0) {}

connection::~connection() {}

void connection::reset()
{
    close();
    last_activity = 0;
    memset(&local_addr, 0, sizeof(local_addr));
    memset(&peer_addr, 0, sizeof(peer_addr));
}

int connection::get_id()
{
    return conn_id;
}

void connection::set_id(int conn_id)
{
    this->conn_id = conn_id;
}

int connection::get_poll_fd()
{
    return sock ? sock->get_fd() : -1;
}

int connection::get_sock_error()
{
    return sock ? sock->get_error() : EIO;
}

void connection::accept(int fd)
{
    nopush = nodelay = 0;
    sock = connected_socket_ptr(new tcp_connected_socket());
    sock->accept(fd);
}

bool connection::connect_to_host(socket_addr addr)
{
    nopush = nodelay = 0;
    sock = connected_socket_ptr(new tcp_connected_socket());
    return sock->connect_to_host(addr);
}

void connection::set_nopush(int nopush)
{
    if (sock) {
        if (this->nopush != nopush) {
            sock->set_nopush(nopush);
            this->nopush = nopush;
        }
    }
}

void connection::set_nodelay(int nodelay)
{
    if (sock) {
        if (this->nodelay != nodelay) {
            sock->set_nodelay(nodelay);
            this->nodelay = nodelay;
        }
    }
}

void connection::start_lingering_close()
{
    if (sock) {
        sock->start_lingering_close();
    }
}

void connection::close()
{
    if (sock) {
        nopush = nodelay = 0;
        sock = connected_socket_ptr();
    }
}

io_result connection::read(void *buf, size_t len)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->read(buf, len);
}

io_result connection::readv(const struct iovec *iov, int iovcnt)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->readv(iov, iovcnt);
}

io_result connection::write(void *buf, size_t len)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->write(buf, len);
}

io_result connection::writev(const struct iovec *iov, int iovcnt)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->writev(iov, iovcnt);
}

time_t connection::get_last_activity() { return last_activity; }
void connection::set_last_activity(time_t current_time) { last_activity = current_time; }
socket_addr& connection::get_local_addr() { return peer_addr; }
socket_addr& connection::get_peer_addr() { return local_addr; }
