//
//  socket.h
//

#ifndef socket_h
#define socket_h

struct unix_socketpair;
typedef std::unique_ptr<unix_socketpair> unix_socketpair_ptr;
typedef std::vector<unix_socketpair_ptr> unix_socketpair_list;

struct listening_socket;
typedef std::unique_ptr<listening_socket> listening_socket_ptr;
typedef std::vector<listening_socket_ptr> listening_socket_list;

struct connected_socket;
typedef std::unique_ptr<connected_socket> connected_socket_ptr;
typedef std::vector<connected_socket_ptr> connected_socket_list;


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
    
    virtual void close_connection();
    virtual void set_fd(int fd);
    virtual int get_fd();
    virtual int get_error();
};


/* unix socketpair
 *
 * used for inter thread/process ipc
 */

enum unix_socketpair_user
{
    unix_socketpair_owner,
    unix_socketpair_client,
};

struct unix_socketpair
{
    generic_socket owner;
    generic_socket client;
    
    unix_socketpair(int buf_size);
    
    generic_socket& owner_sock() { return owner; }
    generic_socket& client_sock() { return client; }
    
    io_result send_message(unix_socketpair_user user, void *buffer, size_t length);
    io_result recv_message(unix_socketpair_user user, void *buffer, size_t length);
};


/* tcp listening socket
 *
 * tcp server socket that listens on a given port
 */
struct listening_socket : generic_socket
{
    socket_addr addr;
    int backlog;
    
    listening_socket(socket_addr addr, int backlog);
    
    bool start_listening();
    
    std::string to_string();
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
    
    bool connect_to_host(socket_addr addr);
    bool set_nopush(bool nopush);
    bool set_nodelay(bool nodelay);
    bool start_lingering_close();
    
    io_result read(void *buf, size_t len);
    io_result readv(const struct iovec *iov, int iovcnt);
    io_result write(void *buf, size_t len);
    io_result writev(const struct iovec *iov, int iovcnt);
};


/* datagram socket
 *
 * UDP datagram socket
 */
struct datagram_socket : generic_socket
{
    socket_addr bind_addr;
    socket_addr connect_addr;
    
    datagram_socket();
    virtual ~datagram_socket();

    bool setIPV6only(int ipv6only = 1);
    bool bind(socket_addr bind_addr);
    bool connect(socket_addr connect_addr);
    
    io_result sendto(const void *buffer, size_t len, const socket_addr &dest_addr);
    io_result send(const void *buffer, size_t len);
    
    io_result recvfrom(void *buffer, size_t len, socket_addr &src_addr);
    io_result recv(void *buffer, size_t len);
};


/* multicast datagram socket
 *
 * UDP multicast datagram socket
 */
struct multicast_datagram_socket : datagram_socket
{    
    socket_addr iface_addr;
    std::vector<socket_addr> mcast_group_list;
    
    multicast_datagram_socket();
    virtual ~multicast_datagram_socket();

    bool set_multicast_iface(const socket_addr &iface_addr);
    bool set_multicast_loop(unsigned char loop = 1);
    bool set_multicast_ttl(unsigned char ttl = 255);
    bool join_multicast_group(const socket_addr &mcast_addr);
    bool leave_multicast_group(const socket_addr &mcast_addr);
};

#endif
