//
//  plat_net.h
//

#ifndef plat_net_h
#define plat_net_h

#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <net/if_dl.h>
#include <net/if_types.h>
#endif

#endif
