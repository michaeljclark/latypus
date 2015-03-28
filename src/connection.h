//
//  connection.h
//

#ifndef connection_h
#define connection_h

/* connection */

struct connection : io_reader, io_writer
{
    virtual ~connection() {}
        
    virtual void reset() = 0;
    virtual int get_id() = 0;
    virtual void set_id(int conn_id) = 0;
    virtual int get_poll_fd() = 0;
    virtual int get_sock_error() = 0;
    virtual void connect_fd(int fd) = 0;
    virtual bool connect_to_host(socket_addr addr) = 0;
    virtual void set_nopush(int nopush) = 0;
    virtual void set_nodelay(int nodelay) = 0;
    virtual void start_lingering_close() = 0;
    virtual void close() = 0;

    virtual time_t get_last_activity() = 0;
    virtual void set_last_activity(time_t current_time) = 0;
    virtual socket_addr& get_local_addr() = 0;
    virtual socket_addr& get_peer_addr() = 0;

    virtual io_result read(void *buf, size_t len) = 0;
    virtual io_result write(void *buf, size_t len) = 0;
};

#endif
