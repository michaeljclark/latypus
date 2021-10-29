//
//  async_tls_echo_server.cc
//
//  c++ -std=c++11 async_tls_echo_server.cc -lcrypto -lssl -o async_tls_echo_server
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
#include <cassert>
#include <cerrno>
#include <csignal>
#include <vector>
#include <map>
#include <algorithm>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

template<typename T> using vector = std::vector<T>;
template<typename K, typename V> using map = std::map<K,V>;

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

struct tls_connection
{
    tls_connection(int fd, SSL *ssl)
        : fd(fd), ssl(ssl), state(ssl_none), save_state(ssl_none) {}
    tls_connection(const tls_connection &o)
        : fd(o.fd), ssl(o.ssl), state(o.state), save_state(ssl_none) {}

    int fd;
    SSL *ssl;
    ssl_state state, save_state;
};

struct tls_echo_server
{
    vector<struct pollfd> poll_vec;
    map<int,tls_connection> tls_connection_map;
    
    void update_state(tls_connection &conn, int events, ssl_state new_state);
    void update_state(tls_connection &conn, int ssl_err);
    void close_connection(tls_connection &conn);
    void mainloop();
};

static void valog(const char* prefix, const char* fmt, va_list args)
{
    vector<char> buf;
    va_list args_dup;
    int len, ret;

    va_copy(args_dup, args);

    len = vsnprintf(NULL, 0, fmt, args);
    assert(len >= 0);
    buf.resize(len + 1);
    ret = vsnprintf(buf.data(), buf.capacity(), fmt, args_dup);
    assert(len == ret);
    if (buf[len - 1] == '\n') buf[len - 1] = '\0';

    fprintf(stderr, "%s: %s\n", prefix, buf.data());
}

static void vlog(const char* prefix, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    valog(prefix, fmt, args);
    va_end(args);
}

static void panic(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    valog("fatal", fmt, args);
    va_end(args);
    exit(9);
}

static void debugf(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    valog("debug", fmt, args);
    va_end(args);
}

static int tls_error(const char *str, size_t len, void *bio)
{
    vlog("tls_error", "%s", str);
    return 0;
}

void tls_echo_server::update_state(tls_connection &conn, int events, ssl_state new_state)
{
    debugf("fd=%d %s -> %s",
              conn.fd, state_names[conn.state], state_names[new_state]);
    conn.state = new_state;
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                           [&] (const struct pollfd &pfd) { return (pfd.fd == conn.fd); });
    if (pi != poll_vec.end()) pi->events = events;
    else panic("file descriptor missing from poll_vec: %d", conn.fd);
}

void tls_echo_server::update_state(tls_connection &conn, int ssl_err)
{
    conn.save_state = conn.state;
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            update_state(conn, POLLIN, ssl_handshake_read);
            break;
        case SSL_ERROR_WANT_WRITE:
            update_state(conn, POLLOUT, ssl_handshake_write);
            break;
        default:
            panic("tls error: %s", ERR_reason_error_string(ERR_get_error()));
            break;
    }
}

void tls_echo_server::close_connection(tls_connection &conn)
{
    debugf("connection closed");
    int fd = conn.fd;
    close(fd);
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                           [fd] (const struct pollfd &pfd) { return pfd.fd == fd; });
    if (pi != poll_vec.end()) poll_vec.erase(pi);
    tls_connection_map.erase(fd);
}

static volatile bool running = 1;

void tls_echo_server::mainloop()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    
    if (SSL_CTX_use_certificate_file(ctx, ssl_cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(tls_error, NULL);
        panic("failed to load certificate: %s", ssl_cert_file);
    } else {
        debugf("loaded cert: %s", ssl_cert_file);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_cb(tls_error, NULL);
        panic("failed to load private key: %s", ssl_key_file);
    } else {
        debugf("loaded key: %s", ssl_key_file);
    }
    
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(listen_port);
    saddr.sin_addr.s_addr = INADDR_ANY;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        panic("socket failed: %s", strerror(errno));
    }
    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)) < 0) {
        panic("setsockopt(SOL_SOCKET, SO_REUSEADDR) failed: %s", strerror(errno));
    }
    if (fcntl(listen_fd, F_SETFD, FD_CLOEXEC) < 0) {
        panic("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
    if (fcntl(listen_fd, F_SETFL, O_NONBLOCK) < 0) {
        panic("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
    socklen_t addr_size = sizeof(sockaddr_in);
    if (bind(listen_fd, (struct sockaddr *) &saddr, addr_size) < 0) {
        panic("bind failed: %s", strerror(errno));
    }
    if (listen(listen_fd, (int)listen_backlog) < 0) {
        panic("listen failed: %s", strerror(errno));
    }

    char saddr_name[32];
    inet_ntop(saddr.sin_family, (void*)&saddr.sin_addr, saddr_name, sizeof(saddr_name));
    debugf("listening on: %s:%d", saddr_name, ntohs(saddr.sin_port));

    char buf[16384];
    int buf_len = 0;
    poll_vec.push_back({listen_fd, POLLIN, 0});
    
    while (running)
    {
        int ret = poll(poll_vec.data(), (int)poll_vec.size(), -1);
        if (ret < 0 && errno != EAGAIN && errno != EINTR)
        {
            panic("poll failed: %s", strerror(errno));
        }
        auto poll_events = poll_vec;
        for (auto &pfd : poll_events)
        {
            if (pfd.fd == listen_fd && (pfd.revents & POLLIN))
            {
                sockaddr_in paddr;
                char paddr_name[32];
                int fd = accept(listen_fd, (struct sockaddr *) &paddr, &addr_size);
                if (fd < 0) {
                    panic("accept failed: %s", strerror(errno));
                }
                
                if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
                    panic("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
                }

                inet_ntop(paddr.sin_family, (void*)&paddr.sin_addr, paddr_name, sizeof(paddr_name));
                debugf("accepted connection from: %s:%d fd=%d",
                          paddr_name, ntohs(paddr.sin_port), fd);
                
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, fd);
                SSL_set_accept_state(ssl);
                
                auto si = tls_connection_map.insert
                    (std::pair<int,tls_connection>
                        (fd, tls_connection(fd, ssl)));
                
                tls_connection &conn = si.first->second;
                poll_vec.push_back({fd, POLLIN, 0});

                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                }
                continue;
            }
            
            auto si = tls_connection_map.find(pfd.fd);
            if (si == tls_connection_map.end()) continue;
            tls_connection &conn = si->second;
            
            if (pfd.revents & (POLLHUP | POLLERR))
            {
                SSL_free(conn.ssl);
                close_connection(conn);
                break;
            }
            else if ((conn.state == ssl_handshake_read ||
                      conn.state == ssl_handshake_write) &&
                     (pfd.revents & (POLLIN | POLLOUT)))
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else {
                    /* we can get a handshake while writing response */
                    if (conn.save_state == ssl_app_write) {
                        update_state(conn, POLLOUT, ssl_app_write);
                    } else {
                        update_state(conn, POLLIN, ssl_app_read);
                    }
                }
            }
            else if (conn.state == ssl_app_read && pfd.revents & POLLIN)
            {
                /* TODO: track input buffer offset to handle partial reads */
                int ret = SSL_read(conn.ssl, buf, sizeof(buf) - 1);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else if (ret == 0) {
                    SSL_free(conn.ssl);
                    close_connection(conn);
                } else {
                    buf_len = ret;
                    buf[buf_len] = '\0';
                    debugf("received: %s", buf);
                    update_state(conn, POLLOUT, ssl_app_write);
                }
            }
            else if (conn.state == ssl_app_write && pfd.revents & POLLOUT)
            {
                /* TODO: track output buffer offset to handle partial writes */
                int ret = SSL_write(conn.ssl, buf, buf_len);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else {
                    debugf("sent: %s", buf);
                    update_state(conn, POLLIN, ssl_app_read);
                }
            }
        }
    }
    debugf("exiting\n");
    SSL_CTX_free(ctx);
}

static void _signal_handler(int signum, siginfo_t *info, void *)
{
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            running = 0;
            break;
        default:
            break;
    }
}

static void _install_signal_handler()
{
    struct sigaction sigaction_handler;
    memset(&sigaction_handler, 0, sizeof(sigaction_handler));
    sigaction_handler.sa_sigaction = _signal_handler;
    sigaction_handler.sa_flags = SA_SIGINFO;
    sigaction(SIGTERM, &sigaction_handler, nullptr);
    sigaction(SIGINT, &sigaction_handler, nullptr);
}

int main(int argc, char **argv)
{
    SSL_library_init();
    SSL_load_error_strings();

    _install_signal_handler();
    
    tls_echo_server server;
    server.mainloop();
}
