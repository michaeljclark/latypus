//
//  openssl_async_echo_server.cc
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
    ssl_connection(int conn_fd, SSL *ssl, BIO *sbio)
        : conn_fd(conn_fd), ssl(ssl), sbio(sbio), state(ssl_none) {}
    ssl_connection(const ssl_connection &o)
        : conn_fd(o.conn_fd), ssl(o.ssl), sbio(o.sbio), state(o.state) {}

    int conn_fd;
    SSL *ssl;
    BIO *sbio;
    ssl_state state;
};

void log_prefix(const char* prefix, const char* fmt, va_list args)
{
    std::vector<char> buf(256);
    int len = vsnprintf(buf.data(), buf.capacity(), fmt, args);
    if (len >= (int)buf.capacity()) {
        buf.resize(len + 1);
        vsnprintf(buf.data(), buf.capacity(), fmt, args);
    }
    fprintf(stderr, "%s: %s\n", prefix, buf.data());
}

void log_fatal_exit(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("fatal", fmt, args);
    va_end(args);
    exit(9);
}

void log_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("error", fmt, args);
    va_end(args);
}

void log_debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_prefix("debug", fmt, args);
    va_end(args);
}

static EVP_PKEY *load_key(BIO *bio_err, const char *file)
{
    BIO *bio_key = BIO_new(BIO_s_file());
    
    if (bio_key == NULL) return NULL;
    
    if (BIO_read_filename(bio_key, file) <= 0) {
        BIO_free(bio_key);
        return NULL;
    }
    
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio_key, NULL, NULL, NULL);
    BIO_free(bio_key);
    
    return key;
}

static X509 *load_cert(BIO *bio_err, const char *file)
{
    BIO *bio_cert = BIO_new(BIO_s_file());

    if (bio_cert == NULL) return NULL;
    
    if (BIO_read_filename(bio_cert, file) <= 0) {
        BIO_free(bio_cert);
        return NULL;
    }
    
    X509 *cert = PEM_read_bio_X509_AUX(bio_cert, NULL, NULL, NULL);
    BIO_free(bio_cert);
    
    return cert;
}

void update_state(struct pollfd &pfd, ssl_connection &ssl_conn, int events, ssl_state new_state)
{
    log_debug("conn_fd=%d %s -> %s",
              pfd.fd, state_names[ssl_conn.state], state_names[new_state]);
    ssl_conn.state = new_state;
    pfd.events = events;
}

void update_state(struct pollfd &pfd, ssl_connection &ssl_conn, int ssl_err)
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
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_server_method());
    
    X509 *cert = load_cert(bio_err, ssl_cert_file);
    if (cert) {
        log_debug("loaded cert: %s", ssl_cert_file);
    } else {
        BIO_print_errors(bio_err);
        log_fatal_exit("error loading certificate: %s", ssl_cert_file);
    }
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        BIO_print_errors(bio_err);
        log_fatal_exit("error using certificate");
    }
    
    EVP_PKEY *key = load_key(bio_err, ssl_key_file);
    if (key) {
        log_debug("loaded key: %s", ssl_key_file);
    } else {
        BIO_print_errors(bio_err);
        log_fatal_exit("error loading private key: %s", ssl_key_file);
    }
    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        BIO_print_errors(bio_err);
        log_fatal_exit("error using private key");
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
    
    while (true) {
        int ret = poll(&poll_vec[0], (int)poll_vec.size(), -1);
        if (ret < 0 && (errno != EAGAIN || errno != EINTR))
        {
            log_error("poll failed: %s", strerror(errno));
            exit(9);
        }
        for (size_t i = 0; i < poll_vec.size(); i++)
        {
            if (poll_vec[i].fd == listen_fd && poll_vec[i].revents & POLLIN)
            {
                sockaddr_in paddr;
                char paddr_name[32];
                int conn_fd = accept(listen_fd, (struct sockaddr *) &paddr, &addr_size);
                inet_ntop(paddr.sin_family, (void*)&paddr.sin_addr, paddr_name, sizeof(paddr_name));
                
                log_debug("accepted connection from: %s:%d fd=%d",
                          paddr_name, ntohs(paddr.sin_port), conn_fd);
                
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, conn_fd);
                SSL_set_accept_state(ssl);
                
                auto si = ssl_connection_map.insert(std::pair<int,ssl_connection>
                                                    (conn_fd, ssl_connection(conn_fd, ssl, NULL /*sbio */)));
                ssl_connection &ssl_conn = si.first->second;
                poll_vec.push_back({conn_fd, POLLIN, 0});
                size_t ni = poll_vec.size() - 1;
                
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[ni], ssl_conn, ssl_err);
                }
                continue;
            }
            
            int conn_fd = poll_vec[i].fd;
            auto si = ssl_connection_map.find(conn_fd);
            if (si == ssl_connection_map.end()) continue;
            ssl_connection &ssl_conn = si->second;
            
            if ((poll_vec[i].revents & POLLHUP) || (poll_vec[i].revents & POLLERR))
            {
                log_debug("connection closed");
                SSL_free(ssl_conn.ssl);
                auto pi = std::find_if(poll_vec.begin(), poll_vec.end(), [conn_fd] (const struct pollfd &pfd){
                    return pfd.fd == conn_fd;
                });
                if (pi != poll_vec.end()) {
                    poll_vec.erase(pi);
                }
            }
            else if (ssl_conn.state == ssl_handshake_read && poll_vec[i].revents & POLLIN)
            {
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
                    update_state(poll_vec[i], ssl_conn, POLLIN, ssl_app_read);
                }
            }
            else if (ssl_conn.state == ssl_handshake_write && poll_vec[i].revents & POLLOUT)
            {
                int ret = SSL_do_handshake(ssl_conn.ssl);
                if (ret < 0) {
                    int ssl_err = SSL_get_error(ssl_conn.ssl, ret);
                    update_state(poll_vec[i], ssl_conn, ssl_err);
                } else {
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
        }
    }
    
    return 0;
}