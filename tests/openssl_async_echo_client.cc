//
//  openssl_async_echo_client.cc
//
//  clang++ -std=c++11 openssl_async_echo_client.cc -lcrypto -lssl -o openssl_async_echo_client
//
//  * example of non-blocking TLS
//  * probably leaks
//  * tested with boringssl
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
    ssl_connection(int conn_fd, SSL *ssl, BIO *sbio)
        : conn_fd(conn_fd), ssl(ssl), sbio(sbio), state(ssl_none) {}
    ssl_connection(const ssl_connection &o)
        : conn_fd(o.conn_fd), ssl(o.ssl), sbio(o.sbio), state(o.state) {}
    
    int conn_fd;
    SSL *ssl;
    BIO *sbio;
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

static void log_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("error", fmt, args);
    va_end(args);
}

static void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("debug", fmt, args);
    va_end(args);
}

static int print_bio(const char *str, size_t len, void *bio)
{
    return BIO_write((BIO *)bio, str, (int)len);
}

static void update_state(struct pollfd &pfd, ssl_connection &ssl_conn, int events, ssl_state new_state)
{
    log_debug("conn_fd=%d %s -> %s",
              pfd.fd, state_names[ssl_conn.state], state_names[new_state]);
    ssl_conn.state = new_state;
    pfd.events = events;
}

static void update_state(struct pollfd &pfd, ssl_connection &ssl_conn, int ssl_err)
{
    switch (ssl_err) {
        case SSL_ERROR_WANT_READ:
            update_state(pfd, ssl_conn, POLLIN, ssl_handshake_read);
            break;
        case SSL_ERROR_WANT_WRITE:
            update_state(pfd, ssl_conn, POLLOUT, ssl_handshake_write);
            break;
        default:
            break;
    }
}

int main(int argc, char **argv)
{
    SSL_library_init();
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());

    if ((!SSL_CTX_load_verify_locations(ctx, ssl_cacert_file, NULL)) ||
        (!SSL_CTX_set_default_verify_paths(ctx))) {
        ERR_print_errors_cb(print_bio, bio_err);
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
    if (connect(connect_fd, (struct sockaddr *) &saddr, addr_size) < 0 && errno != EINPROGRESS) {
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

    ssl_connection_map.insert(std::pair<int,ssl_connection>
                                    (connect_fd, ssl_connection(connect_fd, ssl, NULL /*sbio */)));
    
    while (true)
    {
        int ret = poll(&poll_vec[0], (int)poll_vec.size(), -1);
        if (ret < 0 && (errno != EAGAIN || errno != EINTR))
        {
            log_error("poll failed: %s", strerror(errno));
            exit(9);
        }
        for (size_t i = 0; i < poll_vec.size(); i++)
        {
            int conn_fd = poll_vec[i].fd;
            auto si = ssl_connection_map.find(conn_fd);
            if (si == ssl_connection_map.end()) continue;
            ssl_connection &ssl_conn = si->second;
            
            if ((poll_vec[i].revents & POLLHUP) || (poll_vec[i].revents & POLLERR))
            {
                log_debug("connection closed");
                SSL_free(ssl_conn.ssl);
                close(ssl_conn.conn_fd);
                auto pi = std::find_if(poll_vec.begin(), poll_vec.end(), [conn_fd] (const struct pollfd &pfd){
                    return pfd.fd == conn_fd;
                });
                if (pi != poll_vec.end()) {
                    poll_vec.erase(pi);
                }
            }
            else if (ssl_conn.state == ssl_none && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                }
            }
            else if (ssl_conn.state == ssl_handshake_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
                    update_state(poll_vec[i], ssl_conn, POLLOUT, ssl_app_write);
                }
            }
            else if (ssl_conn.state == ssl_handshake_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
                    update_state(poll_vec[i], ssl_conn, POLLOUT, ssl_app_write);
                }
            }
            else if (ssl_conn.state == ssl_app_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_write(ssl_conn.ssl, buf, buf_len);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
                    printf("sent: %s", buf);
                    update_state(poll_vec[i], ssl_conn, POLLIN, ssl_app_read);
                }
            }
            else if (ssl_conn.state == ssl_app_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_read(ssl_conn.ssl, buf, sizeof(buf) - 1);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
                    buf_len = ret;
                    buf[buf_len] = '\0';
                    printf("received: %s", buf);
                    
                    SSL_free(ssl_conn.ssl);
                    // TODO - we should probably shutdown gracefully
                    // SSL_shutdown(ssl_conn.ssl);
                    close(ssl_conn.conn_fd);
                    auto pi = std::find_if(poll_vec.begin(), poll_vec.end(), [conn_fd] (const struct pollfd &pfd){
                        return pfd.fd == conn_fd;
                    });
                    if (pi != poll_vec.end()) {
                        poll_vec.erase(pi);
                    }
                    return 0;
                }
            }
        }
    }

    return 0;
}
