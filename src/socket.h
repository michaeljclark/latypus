//
//  socket.h
//

#ifndef socket_h
#define socket_h

struct unix_socketpair;
typedef std::unique_ptr<unix_socketpair> unix_socketpair_ptr;
typedef std::vector<unix_socketpair_ptr> unix_socketpair_list;

struct connected_socket;
typedef std::unique_ptr<connected_socket> connected_socket_ptr;
typedef std::vector<connected_socket_ptr> connected_socket_list;

enum socket_mode
{
    socket_mode_plain,
    socket_mode_tls
};

/* socket addr
 */

union socket_addr {
    struct sockaddr saddr;
    struct sockaddr_in ip4addr;
    struct sockaddr_in6 ip6addr;
    struct sockaddr_storage storage;
    
    static socklen_t len(const socket_addr &addr);
    static std::string addr_to_string(const socket_addr &addr);
    static int string_to_addr(std::string addr_spec, socket_addr &addr);
    
    inline bool operator==(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) == 0; }
    inline bool operator!=(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) != 0; }
    inline bool operator<(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) < 0; }
    inline bool operator<=(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) <= 0; }
    inline bool operator>(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) > 0; }
    inline bool operator>=(const socket_addr &o) const { return memcmp(this, &o, sizeof(*this)) >= 0; }
};


/* generic socket
 *
 * base class for all sockets
 */
struct generic_socket
{
    int fd;
    
    generic_socket();
    generic_socket(int fd);
    virtual ~generic_socket();
    
    virtual void set_context(void *context);
    virtual socket_mode get_mode();
    virtual void close_connection();
    virtual void set_fd(int fd);
    virtual int get_fd();
    virtual int get_error();
};


/* tcp connected socket
 *
 * accepted tcp client connection socket
 */
struct connected_socket : generic_socket, io_reader, io_writer
{
    unsigned int lingering_close : 1;
    unsigned int nopush : 1;
    unsigned int nodelay : 1;

    connected_socket();
    connected_socket(int fd);
    virtual ~connected_socket();

    virtual void accept(int fd) = 0;
    virtual bool start_listening(socket_addr addr, int backlog) = 0;
    virtual socket_addr get_addr() = 0;
    virtual std::string to_string() = 0;

    virtual bool connect_to_host(socket_addr addr) = 0;
    virtual bool set_nopush(bool nopush) = 0;
    virtual bool set_nodelay(bool nodelay) = 0;
    virtual bool start_lingering_close() = 0;
};

#endif
