//
//  socket_udp.h
//

#ifndef socket_udp_h
#define socket_udp_h

/* datagram socket
 *
 * UDP datagram socket
 */
struct udp_datagram_socket : generic_socket
{
    socket_addr bind_addr;
    socket_addr connect_addr;
    
    udp_datagram_socket();
    virtual ~udp_datagram_socket();
    
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
struct multicast_udp_datagram_socket : udp_datagram_socket
{
    socket_addr iface_addr;
    std::vector<socket_addr> mcast_group_list;
    
    multicast_udp_datagram_socket();
    virtual ~multicast_udp_datagram_socket();
    
    bool set_multicast_iface(const socket_addr &iface_addr);
    bool set_multicast_loop(unsigned char loop = 1);
    bool set_multicast_ttl(unsigned char ttl = 255);
    bool join_multicast_group(const socket_addr &mcast_addr);
    bool leave_multicast_group(const socket_addr &mcast_addr);
};

#endif
