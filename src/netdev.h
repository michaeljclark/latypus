///
//  netdev.h
//

#ifndef netdev_h
#define netdev_h

enum if_flag
{
    if_flag_none = 0x0,
    if_flag_up = 0x1,                   /* equivalent to BSD/Linux IFF_UP */
    if_flag_broadcast = 0x2,            /* equivalent to BSD/Linux IFF_BROADCAST */
    if_flag_loopback = 0x8,             /* equivalent to BSD/Linux IFF_LOOPBACK */
    if_flag_point_to_point = 0x10,      /* equivalent to BSD/Linux IFF_POINTOPOINT */
    if_flag_running = 0x40,             /* equivalent to BSD/Linux IFF_RUNNING */
    if_flag_multicast = 0x8000,         /* equivalent to BSD IFF_MULTICAST, IFF_MULTICAST on Linux is 0x1000 */
};

struct if_flag_name {
    int flag;
    const char* name;
};

struct if_info
{
    typedef std::shared_ptr<if_info> ptr;
    
    static if_flag_name flag_names[];
    
    std::string                 if_name;
    unsigned int                if_flags;
    std::vector<unsigned char>  if_hwaddr;
    std::vector<socket_addr>    if_addrs;
    
    if_info(std::string if_name, int if_flags) : if_name(if_name), if_flags(if_flags), if_hwaddr(), if_addrs() {}

    static int hexname(const u_int8_t *cp, size_t len, char *host, size_t hostlen);
    static std::string flags_to_string(int if_flags);

    void print();
};

struct netdev
{    
    static std::vector<if_info::ptr> getInterfaceInfo();
    static std::vector<if_info::ptr> getInterfaceInfo(size_t addr_count, int if_flags);
    static void init();
};

#endif
