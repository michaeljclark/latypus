//
//  socket_tcp.h
//

#ifndef socket_tcp_h
#define socket_tcp_h


/* tcp_connected_socket */

struct tcp_connected_socket : connected_socket
{
    socket_addr addr;
    int backlog;
    
    unsigned int lingering_close : 1;
    unsigned int nopush : 1;
    unsigned int nodelay : 1;
    
    tcp_connected_socket();
    tcp_connected_socket(int fd);
    virtual ~tcp_connected_socket();

    void set_context(void *context);
    socket_mode get_mode();
    int do_handshake();
    bool accept(int fd);
    bool start_listening(socket_addr addr, int backlog);
    socket_addr get_addr();
    std::string to_string();
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
