//
//  netdev.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <cassert>
#include <sstream>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <map>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "netdev.h"

if_flag_name if_info::flag_names[] = {
    { if_flag_up,               "UP"},
    { if_flag_broadcast,        "BROADCAST"},
    { if_flag_loopback,         "LOOPBACK"},
    { if_flag_point_to_point,   "POINTOPOINT"},
    { if_flag_running,          "RUNNING"},
    { if_flag_multicast,        "MULTICAST"},
    { if_flag_none,             nullptr},
};

int if_info::hexname(const u_int8_t *cp, size_t len, char *host, size_t hostlen)
{
    char *outp = host;    
    *outp = '\0';
    for (size_t i = 0; i < len; i++) {
        int n = snprintf(outp, hostlen, "%s%02x", i ? ":" : "", cp[i]);
        if (n < 0 || n >= (int)hostlen) {
            *host = '\0';
            return EAI_MEMORY;
        }
        outp += n;
        hostlen -= n;
    }
    return 0;
}

std::string if_info::flags_to_string(int if_flags)
{
    std::stringstream ss;
    if_flag_name *info = flag_names;
    while (info->flag != if_flag_none) {
        if (info->flag & if_flags) {
            if (ss.str().length() > 0) ss << ",";
            ss << info->name;
        }
        info++;
    }
    return ss.str();
}

std::vector<if_info::ptr> netdev::getInterfaceInfo()
{
    std::map<std::string,if_info::ptr> ifInfoMap;
    
    struct ifaddrs *ifaddr, *ifa;
    int n;

#if defined (__linux__)
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0) {
        log_fatal_exit("socket: %s\n", strerror(s));
    }
#endif
    
    if (getifaddrs(&ifaddr) == -1) {
        log_fatal_exit("getifaddrs: %s", strerror(errno));
    }
    
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL) continue;
        
        int family = ifa->ifa_addr->sa_family;
        
        auto ift = ifInfoMap.find(ifa->ifa_name);
        if_info::ptr ifInfo;
        if (ift == ifInfoMap.end()) {
            int ifFlags = 0;
            if (ifa->ifa_flags & IFF_UP) ifFlags |= if_flag_up;
            if (ifa->ifa_flags & IFF_BROADCAST) ifFlags |= if_flag_broadcast;
            if (ifa->ifa_flags & IFF_LOOPBACK) ifFlags |= if_flag_loopback;
            if (ifa->ifa_flags & IFF_POINTOPOINT) ifFlags |= if_flag_point_to_point;
            if (ifa->ifa_flags & IFF_RUNNING) ifFlags |= if_flag_running;
            if (ifa->ifa_flags & IFF_MULTICAST) ifFlags |= if_flag_multicast;
            ifInfo = std::make_shared<if_info>(ifa->ifa_name, ifFlags);
            ifInfoMap.insert(std::pair<std::string,if_info::ptr>(ifa->ifa_name, ifInfo));
        } else {
            ifInfo = ift->second;
        }
        
        if (family == AF_INET) {
            socket_addr saddr;
            memcpy(&saddr, ifa->ifa_addr, sizeof(struct sockaddr_in));
            ifInfo->if_addrs.emplace_back(saddr);
        }
        else if (family == AF_INET6)
        {
            socket_addr saddr;
            memcpy(&saddr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            ifInfo->if_addrs.emplace_back(saddr);
        }
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)
        else if (family == AF_LINK)
        {
            const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)(const void *)ifa->ifa_addr;
            if (sdl->sdl_type == IFT_ETHER) {
                ifInfo->if_hwaddr.resize((size_t)sdl->sdl_alen);
                memcpy(&ifInfo->if_hwaddr[0], (u_int8_t *)LLADDR(sdl), (size_t)sdl->sdl_alen);
            }
        }
#else
        else if (family == AF_PACKET)
        {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            memcpy(ifr.ifr_name, ifa->ifa_name, strlen(ifa->ifa_name) + 1);
            if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
                log_fatal_exit("ioctl(SIOCGIFHWADDR,%s): %s\n", ifa->ifa_name, strerror(s));
            }
            
            static unsigned char zero_hw_addr[IFHWADDRLEN] = { 0 };
            if (memcmp(ifr.ifr_hwaddr.sa_data, zero_hw_addr, IFHWADDRLEN) != 0) {
                ifInfo->if_hwaddr.resize((size_t)IFHWADDRLEN);
                memcpy(&ifInfo->if_hwaddr[0], (u_int8_t *)ifr.ifr_hwaddr.sa_data, (size_t)IFHWADDRLEN);
            }
        }
#endif
    }

#if defined (__linux__)
    close(s);
#endif

    freeifaddrs(ifaddr);

    std::vector<if_info::ptr> ifInfoList;
    for (auto ent : ifInfoMap) {
        ifInfoList.emplace_back(ent.second);
    }
    return ifInfoList;
}

void if_info::print()
{
    char host[NI_MAXHOST];
    log_debug("iface: %s", if_name.c_str());
    log_debug("\t\t   status: %s", flags_to_string(if_flags).c_str());
    if (if_hwaddr.size() > 0) {
        hexname((u_int8_t *)&if_hwaddr[0], (size_t)if_hwaddr.size(), host, sizeof(host));
        log_debug("\t\t   hwaddr: %s", host);
    }
    for (auto if_addr : if_addrs) {
        if (if_addr.saddr.sa_family == AF_INET) {
            int s = getnameinfo(&if_addr.saddr,
                                sizeof(struct sockaddr_in),
                                host, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_fatal_exit("getnameinfo: %s", strerror(s));
            }
            log_debug("\t\tipv4_addr: %s", host);
        }
        if (if_addr.saddr.sa_family == AF_INET6) {
            int s = getnameinfo(&if_addr.saddr,
                                sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                log_fatal_exit("getnameinfo: %s", strerror(s));
            }
            log_debug("\t\tipv6_addr: [%s]", host);
        }
    }
}

std::vector<if_info::ptr> netdev::getInterfaceInfo(size_t addr_count, int if_flags)
{
    std::vector<if_info::ptr> ifInfoList = getInterfaceInfo();
    std::vector<if_info::ptr> filteredIfInfoList;
    for (auto &ifInfo : ifInfoList) {
        if (ifInfo->if_addrs.size() >= addr_count && (int)(ifInfo->if_flags & if_flags) == if_flags) {
            filteredIfInfoList.push_back(ifInfo);
        }
    }
    return filteredIfInfoList;
}

void netdev::init()
{
    std::vector<if_info::ptr> ifInfoList = getInterfaceInfo(1, if_flag_up | if_flag_running);
    for (auto &ifInfo : ifInfoList) {
        ifInfo->print();
    }
}
