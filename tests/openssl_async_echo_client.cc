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

static void update_state(struct pollfd &pfd, ssl_connection &conn,
                         int events, ssl_state new_state)
{
    log_debug("fd=%d %s -> %s",
              pfd.fd, state_names[conn.state], state_names[new_state]);
    conn.state = new_state;
    pfd.events = events;
}

static void update_state(struct pollfd &pfd, ssl_connection &conn,
                         int ssl_err)
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
        return false;
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
    std::vector<struct pollfd> poll_vec;
    std::map<int,ssl_connection> ssl_connection_map;
    poll_vec.push_back({connect_fd, POLLOUT, 0});
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connect_fd);
    SSL_set_connect_state(ssl);

    ssl_connection_map.insert
        (std::pair<int,ssl_connection>
            (connect_fd, ssl_connection(connect_fd, ssl)));
    
    while (true)
    {
        int ret = poll(&poll_vec[0], (int)poll_vec.size(), -1);
        if (ret < 0 && (errno != EAGAIN || errno != EINTR))
        {
            log_fatal_exit("poll failed: %s", strerror(errno));
            exit(9);
        }
        for (size_t i = 0; i < poll_vec.size(); i++)
        {
            int fd = poll_vec[i].fd;
            auto si = ssl_connection_map.find(fd);
            if (si == ssl_connection_map.end()) continue;
            ssl_connection &conn = si->second;
            
            if ((poll_vec[i].revents & POLLHUP) || (poll_vec[i].revents & POLLERR))
            {
                log_debug("connection closed");
                SSL_free(conn.ssl);
                close(conn.fd);
                auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                    [fd] (const struct pollfd &pfd) { return pfd.fd == fd; });
                if (pi != poll_vec.end()) poll_vec.erase(pi);
            }
            else if (conn.state == ssl_none && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                }
            }
            else if (conn.state == ssl_handshake_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
                    update_state(poll_vec[i], conn, POLLOUT, ssl_app_write);
                }
            }
            else if (conn.state == ssl_handshake_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(conn.ssl, ret);
                    update_state(poll_vec[i], conn, ssl_err);
                } else {
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
                    
                    // TODO - we should probably shutdown gracefully
                    // SSL_shutdown(conn.ssl);
                    SSL_free(conn.ssl);
                    close(conn.fd);
                    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(),
                            [fd] (const struct pollfd &pfd) { return pfd.fd == fd; });
                    if (pi != poll_vec.end()) poll_vec.erase(pi);
                    
                    // exit
                    return 0;
                }
            }
        }
    }

    return 0;
}
