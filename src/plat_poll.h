//
//  plat_poll.h
//

#ifndef plat_poll_h
#define plat_poll_h

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>

#if defined(__linux__)
#include <sys/epoll.h>
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/event.h>
#endif

#endif
