//
//  unix_socket.cc
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
#include "socket_unix.h"


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
