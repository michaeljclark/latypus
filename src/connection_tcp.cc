//
//  connection_tcp.cc
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
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "pollset_poll.h"
#include "pollset_kqueue.h"
#include "protocol.h"
#include "connection.h"
#include "connection_tcp.h"


/* connection_tcp */

connection_tcp::connection_tcp() : conn_id(-1), last_activity(0), local_addr(), peer_addr(), nopush(0), nodelay(0) {}

connection_tcp::~connection_tcp() {}

void connection_tcp::reset()
{
    close();
    last_activity = 0;
    memset(&local_addr, 0, sizeof(local_addr));
    memset(&peer_addr, 0, sizeof(peer_addr));
}

int connection_tcp::get_id()
{
    return conn_id;
}

void connection_tcp::set_id(int conn_id)
{
    this->conn_id = conn_id;
}

int connection_tcp::get_poll_fd()
{
    return sock ? sock->get_fd() : -1;
}

int connection_tcp::get_sock_error()
{
    return sock ? sock->get_error() : EIO;
}

void connection_tcp::connect_fd(int fd)
{
    nopush = nodelay = 0;
    // TODO - use std::unqiue_ptr
    sock = std::make_shared<connected_socket>(fd);
}

bool connection_tcp::connect_to_host(socket_addr addr)
{
    nopush = nodelay = 0;
    // TODO - use std::unqiue_ptr
    sock = std::make_shared<connected_socket>();
    return sock->connect_to_host(addr);
}

void connection_tcp::set_nopush(int nopush)
{
    if (sock) {
        if (this->nopush != nopush) {
            sock->set_nopush(nopush);
            this->nopush = nopush;
        }
    }
}

void connection_tcp::set_nodelay(int nodelay)
{
    if (sock) {
        if (this->nodelay != nodelay) {
            sock->set_nodelay(nodelay);
            this->nodelay = nodelay;
        }
    }
}

void connection_tcp::start_lingering_close()
{
    if (sock) {
        sock->start_lingering_close();
    }
}

void connection_tcp::close()
{
    if (sock) {
        nopush = nodelay = 0;
        sock = connected_socket_ptr();
    }
}

io_result connection_tcp::read(void *buf, size_t len)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->read(buf, len);
}

io_result connection_tcp::readv(const struct iovec *iov, int iovcnt)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->readv(iov, iovcnt);
}

io_result connection_tcp::write(void *buf, size_t len)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->write(buf, len);
}

io_result connection_tcp::writev(const struct iovec *iov, int iovcnt)
{
    if (!sock) {
        return io_result(io_error(EIO));
    }
    return sock->writev(iov, iovcnt);
}

time_t connection_tcp::get_last_activity() { return last_activity; }
void connection_tcp::set_last_activity(time_t current_time) { last_activity = current_time; }
socket_addr& connection_tcp::get_local_addr() { return peer_addr; }
socket_addr& connection_tcp::get_peer_addr() { return local_addr; }
