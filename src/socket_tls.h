//
//  socket_tls.h
//

#ifndef socket_tls_h
#define socket_tls_h

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* tls_connected_socket */

struct tls_connected_socket : connected_socket
{
    socket_addr addr;
    int backlog;
    SSL_CTX *ctx;
    SSL *ssl;

    unsigned int lingering_close : 1;
    unsigned int nopush : 1;
    unsigned int nodelay : 1;
    
    tls_connected_socket();
    tls_connected_socket(int fd);
    virtual ~tls_connected_socket();
    
    bool start_listening(socket_addr addr, int backlog);
    socket_addr get_addr();
    std::string to_string();

    void set_context(void *context);
    socket_mode get_mode();
    int do_handshake();
    void close_connection();
    void accept(int fd);
    bool connect_to_host(socket_addr addr);
    bool set_nopush(bool nopush);
    bool set_nodelay(bool nodelay);
    bool start_lingering_close();
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
};

#endif
