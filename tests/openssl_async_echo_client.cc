//
//  openssl_async_echo_client.cc
//
//  clang++ -std=c++11 openssl_async_echo_client.cc -lcrypto -lssl -o openssl_async_echo_client
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


static const char* connect_host = "127.0.0.1";
static int connect_port = 8443;

static const char* ssl_cacert_file = "ssl/cacert.pem";

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
        : fd(fd), ssl(ssl), state(ssl_none) {}
    tls_connection(const tls_connection &o)
        : fd(o.fd), ssl(o.ssl), state(o.state) {}
    
    int fd;
    SSL *ssl;
    ssl_state state;
};

struct tls_echo_client
{
    std::vector<struct pollfd> poll_vec;
    std::map<int,tls_connection> tls_connection_map;
    
    void update_state(tls_connection &conn, int events, ssl_state new_state);
    void update_state(tls_connection &conn, int ssl_err);
    void close_connection(tls_connection &conn);
    void mainloop();
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

void tls_echo_client::update_state(tls_connection &conn, int events, ssl_state new_state)
{
    log_debug("fd=%d %s -> %s",
              conn.fd, state_names[conn.state], state_names[new_state]);
    conn.state = new_state;
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                           [&] (const struct pollfd &pfd) { return pfd.fd == conn.fd; });
    if (pi != poll_vec.end()) pi->events = events;
    else log_fatal_exit("file descriptor missing from poll_vec: %d", conn.fd);
}

void tls_echo_client::update_state(tls_connection &conn, int ssl_err)
{
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            update_state(conn, POLLIN, ssl_handshake_read);
            break;
        case SSL_ERROR_WANT_WRITE:
            update_state(conn, POLLOUT, ssl_handshake_write);
            break;
        default:
            SSL_load_error_strings();
            log_fatal_exit("tls error: %s", ERR_reason_error_string(ERR_get_error()));
            break;
    }
}

void tls_echo_client::close_connection(tls_connection &conn)
{
    log_debug("connection closed");
    int fd = conn.fd;
    close(fd);
    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                           [fd] (const struct pollfd &pfd) { return pfd.fd == fd; });
    if (pi != poll_vec.end()) poll_vec.erase(pi);
    tls_connection_map.erase(fd);
}

void tls_echo_client::mainloop()
{
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());

    if ((!SSL_CTX_load_verify_locations(ctx, ssl_cacert_file, NULL)) ||
        (!SSL_CTX_set_default_verify_paths(ctx))) {
        ERR_print_errors_cb(log_tls_errors, NULL);
        log_fatal_exit("failed to load cacert: %s", ssl_cacert_file);
    } else {
        log_debug("loaded cacert: %s", ssl_cacert_file);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 9);

    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(connect_port);
    
    struct hostent *he = gethostbyname(connect_host);
    if (he) {
        if (he->h_addrtype == AF_INET) {
            memcpy(&saddr.sin_addr, he->h_addr_list[0], he->h_length);
        } else {
            log_fatal_exit("unknown address type: %s", he->h_addrtype);
        }
    } else {
        log_fatal_exit("unknown host %s", connect_host);
    }

    int connect_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect_fd < 0) {
        log_fatal_exit("socket failed: %s", strerror(errno));
    }
    if (fcntl(connect_fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_fatal_exit("fcntl(F_SETFD, FD_CLOEXEC) failed: %s", strerror(errno));
    }
    if (fcntl(connect_fd, F_SETFL, O_NONBLOCK) < 0) {
        log_fatal_exit("fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
    }
    socklen_t addr_size = sizeof(sockaddr_in);
    if (connect(connect_fd, (struct sockaddr *) &saddr, addr_size) < 0 &&
            errno != EINPROGRESS) {
        log_fatal_exit("connect failed: %s", strerror(errno));
    }
    
    char saddr_name[32];
    inet_ntop(saddr.sin_family, (void*)&saddr.sin_addr, saddr_name, sizeof(saddr_name));
    log_debug("connecting to: %s:%d", saddr_name, ntohs(saddr.sin_port));

    char buf[16384] = "Hello World\n";
    int buf_len = (int)strlen(buf);
    poll_vec.push_back({connect_fd, POLLOUT, 0});
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connect_fd);
    SSL_set_connect_state(ssl);

    tls_connection_map.insert
        (std::pair<int,tls_connection>
            (connect_fd, tls_connection(connect_fd, ssl)));
    
    while (true)
    {
        int ret = poll(poll_vec.data(), (int)poll_vec.size(), -1);
        if (ret < 0 && (errno != EAGAIN || errno != EINTR))
        {
            log_fatal_exit("poll failed: %s", strerror(errno));
            exit(9);
        }
        auto poll_events = poll_vec;
        for (auto &pfd : poll_events)
        {
            auto si = tls_connection_map.find(pfd.fd);
            if (si == tls_connection_map.end()) continue;
            tls_connection &conn = si->second;
            
            if (pfd.revents & (POLLHUP | POLLERR))
            {
                close_connection(conn);
                break;
            }
            else if ((conn.state == ssl_none ||
                      conn.state == ssl_handshake_read ||
                      conn.state == ssl_handshake_write) &&
                     (pfd.revents & (POLLIN | POLLOUT)))
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else {
                    update_state(conn, POLLOUT, ssl_app_write);
                }
            }
            else if (conn.state == ssl_app_write && pfd.revents & POLLOUT)
            {
                int ret = SSL_write(conn.ssl, buf, buf_len);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else {
                    printf("sent: %s", buf);
                    update_state(conn, POLLIN, ssl_app_read);
                }
            }
            else if (conn.state == ssl_app_read && pfd.revents & POLLIN)
            {
                int ret = SSL_read(conn.ssl, buf, sizeof(buf) - 1);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(conn, ssl_err);
                } else {
                    buf_len = ret;
                    buf[buf_len] = '\0';
                    printf("received: %s", buf);
                    
                    // TODO - we should probably shutdown gracefully
                    // SSL_shutdown(conn.ssl);
                    close_connection(conn);
                    
                    // exit
                    return;
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    SSL_library_init();
    SSL_load_error_strings();
    
    tls_echo_client client;
    client.mainloop();
}
