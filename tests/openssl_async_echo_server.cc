//
//  openssl_async_echo_server.cc
//
//  clang++ -std=c++11 openssl_async_echo_server.cc -lcrypto -lssl -o openssl_async_echo_server
//
//  * example of non-blocking TLS
//  * tested with openssl/boringssl
//  * probably leaks
//

#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <vector>
#include <map>
#include <algorithm>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


static int listen_port = 8443;
static int listen_backlog = 128;

static const char* ssl_cert_file = "ssl/cert.pem";
static const char* ssl_key_file = "ssl/key.pem";

enum ssl_state
{
    ssl_none,
    ssl_handshake_read,
    ssl_handshake_write,
    ssl_app_read,
    ssl_app_write
};

static const char* state_names[] =
{
    "ssl_none",
    "ssl_handshake_read",
    "ssl_handshake_write",
    "ssl_app_read",
    "ssl_app_write"
};

struct ssl_connection
{
    ssl_connection(int fd, SSL *ssl)
        : fd(fd), ssl(ssl), state(ssl_none) {}
    ssl_connection(const ssl_connection &o)
        : fd(o.fd), ssl(o.ssl), state(o.state) {}

    int fd;
    SSL *ssl;
    ssl_state state;
};

static void log_prefix(const char* prefix, const char* fmt, va_list args)
{
    std::vector<char> buf(256);
    int len = vsnprintf(buf.data(), buf.capacity(), fmt, args);
    if (len >= (int)buf.capacity()) {
        buf.resize(len + 1);
        vsnprintf(buf.data(), buf.capacity(), fmt, args);
    }
    fprintf(stderr, "%s: %s\n", prefix, buf.data());
}

static void log_fatal_exit(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("fatal", fmt, args);
    va_end(args);
    exit(9);
}

static void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("debug", fmt, args);
    va_end(args);
}

static int log_tls_errors(const char *str, size_t len, void *bio)
{
    fprintf(stderr, "%s", str);
    return 0;
}

static void update_state(struct pollfd &pfd, ssl_connection &conn, int events, ssl_state new_state)
{
    log_debug("fd=%d %s -> %s",
              pfd.fd, state_names[conn.state], state_names[new_state]);
    conn.state = new_state;
    pfd.events = events;
}

static void update_state(struct pollfd &pfd, ssl_connection &conn, int ssl_err)
{
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            update_state(pfd, conn, POLLIN, ssl_handshake_read);
            break;
        case SSL_ERROR_WANT_WRITE:
            update_state(pfd, conn, POLLOUT, ssl_handshake_write);
            break;
        default:
            log_fatal_exit("unknown tls error: %d", ssl_err);
            break;
    }
}

int main(int argc, char **argv)
{
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_server_method());
    
    if (SSL_CTX_use_certificate_file(ctx, ssl_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(log_tls_errors, NULL);
        log_fatal_exit("failed to load certificate: %s", ssl_cert_file);
    } else {
        log_debug("loaded cert: %s", ssl_cert_file);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(log_tls_errors, NULL);
        log_fatal_exit("failed to load private key: %s", ssl_key_file);
    } else {
        log_debug("loaded key: %s", ssl_key_file);
    }
    
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(listen_port);
    saddr.sin_addr.s_addr = INADDR_ANY;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_fatal_exit("socket failed: %s", strerror(errno));
    }
    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) < 0) {
        log_fatal_exit("setsockopt(SOL_SOCKET, SO_REUSEADDR) failed: %s", strerror(errno));
    }
    if (fcntl(listen_fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_fatal_exit("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
    if (fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
        log_fatal_exit("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
    socklen_t addr_size = sizeof(sockaddr_in);
    if (bind(listen_fd, (struct sockaddr *) &saddr, addr_size) < 0) {
        log_fatal_exit("bind failed: %s", strerror(errno));
    }
    if (listen(listen_fd, (int)listen_backlog) < 0) {
        log_fatal_exit("listen failed: %s", strerror(errno));
    }

    char saddr_name[32];
    inet_ntop(saddr.sin_family, (void*)&saddr.sin_addr, saddr_name, sizeof(saddr_name));
    log_debug("listening on: %s:%d", saddr_name, ntohs(saddr.sin_port));

    char buf[16384];
    int buf_len = 0;
    std::vector<struct pollfd> poll_vec;
    std::map<int,ssl_connection> ssl_connection_map;
    poll_vec.push_back({listen_fd, POLLIN, 0});
    
    while (true)
    {
        int ret = poll(&poll_vec[0], (int)poll_vec.size(), -1);
        if (ret < 0 && (errno != EAGAIN || errno != EINTR))
        {
            log_fatal_exit("poll failed: %s", strerror(errno));
        }
        for (size_t i = 0; i < poll_vec.size(); i++)
        {
            if (poll_vec[i].fd == listen_fd && poll_vec[i].revents & POLLIN)
            {
                sockaddr_in paddr;
                char paddr_name[32];
                int fd = accept(listen_fd, (struct sockaddr *) &paddr, &addr_size);
                inet_ntop(paddr.sin_family, (void*)&paddr.sin_addr, paddr_name, sizeof(paddr_name));
                
                log_debug("accepted connection from: %s:%d fd=%d",
                          paddr_name, ntohs(paddr.sin_port), fd);
                
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, fd);
                SSL_set_accept_state(ssl);
                
                auto si = ssl_connection_map.insert
                    (std::pair<int,ssl_connection>
                        (fd, ssl_connection(fd, ssl)));
                
                ssl_connection &conn = si.first->second;
                poll_vec.push_back({fd, POLLIN, 0});
                size_t ni = poll_vec.size() - 1;
                
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[ni], conn, ssl_err);
                }
                continue;
            }
            
            int fd = poll_vec[i].fd;
            auto si = ssl_connection_map.find(fd);
            if (si == ssl_connection_map.end()) continue;
            ssl_connection &conn = si->second;
            
            if ((poll_vec[i].revents & POLLHUP) || (poll_vec[i].revents & POLLERR))
            {
                log_debug("connection closed");
                SSL_free(conn.ssl);
                // TODO - crashes on subsequent connections in SSL_do_handshake
                //        if we close the connection file descriptor.
                //        ssl_lib.c::SSL_do_handshake::s->method->ssl_renegotiate_check(s);
                //        Why? reuse of same fd number for subsequent connection?
                //        comment the following line and the server works but leaks fds
                close(conn.fd);
                auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                    [fd] (const struct pollfd &pfd) { return pfd.fd == fd; });
                if (pi != poll_vec.end()) poll_vec.erase(pi);
            }
            else if (conn.state == ssl_handshake_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
                    update_state(poll_vec[i], conn, POLLIN, ssl_app_read);
                }
            }
            else if (conn.state == ssl_handshake_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
                    update_state(poll_vec[i], conn, POLLIN, ssl_app_read);
                }
            }
            else if (conn.state == ssl_app_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_read(conn.ssl, buf, sizeof(buf) - 1);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
                    buf_len = ret;
                    buf[buf_len] = '\0';
                    printf("received: %s", buf);
                    update_state(poll_vec[i], conn, POLLOUT, ssl_app_write);
                }
            }
            else if (conn.state == ssl_app_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_write(conn.ssl, buf, buf_len);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
                    printf("sent: %s", buf);
                    update_state(poll_vec[i], conn, POLLIN, ssl_app_read);
                }
            }
        }
    }
    
    return 0;
}
