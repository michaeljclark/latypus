//
//  connection.h
//

#ifndef connection_h
#define connection_h

struct connection : io_reader, io_writer
{
    int                     conn_id;
    time_t                  last_activity;
    socket_addr             local_addr;
    socket_addr             peer_addr;
    connected_socket_ptr    sock;
    int                     nopush : 1;
    int                     nodelay : 1;
    
    connection();
    virtual ~connection();

    void reset();
    int get_id();
    void set_id(int conn_id);
    int get_poll_fd();
    int get_sock_error();
    void connect_fd(int fd);
    bool connect_to_host(socket_addr addr);
    void set_nopush(int nopush);
    void set_nodelay(int nodelay);
    void start_lingering_close();
    void close();
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);

    time_t get_last_activity();
    void set_last_activity(time_t current_time);
    socket_addr& get_local_addr();
    socket_addr& get_peer_addr();
};

#endif
