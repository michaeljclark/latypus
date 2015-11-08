//
//  pollset_epoll.cc
//

#if defined(__linux__)

#include "plat_poll.h"

#include <cassert>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include <sys/resource.h>

#include "io.h"
#include "log.h"
#include "socket.h"
#include "pollset.h"
#include "pollset_epoll.h"

const int pollset_epoll::max_events = 48;

pollset_epoll::pollset_epoll()
{
    epoll_fd = epoll_create(max_events);
    eevents.resize(max_events);
    
    struct rlimit rlimit_nofile;
    if (getrlimit(RLIMIT_NOFILE, &rlimit_nofile) < 0) {
        log_fatal_exit("getrlimit(RLIMIT_NOFILE): %s", strerror(errno));
    }
    
    pollobjects_map.resize(rlimit_nofile.rlim_max);
}

pollset_epoll::~pollset_epoll()
{
    close(epoll_fd);
}

const std::vector<poll_object>& pollset_epoll::get_objects()
{
    pollobjects.resize(0);
    for (auto &ent : pollobjects_map) {
        if (ent.fd != -1) pollobjects.push_back(ent);
    }
    return pollobjects;
}

bool pollset_epoll::add_object(poll_object obj, int events)
{
    int epoll_op;
    auto &ent = pollobjects_map[obj.fd];
    if (ent.fd != -1) {
        epoll_op = EPOLL_CTL_MOD;
    } else {
        epoll_op = EPOLL_CTL_ADD;
        pollobjects_map[obj.fd] = obj;
    }
    
    struct epoll_event eevt;
    memset(&eevt, 0, sizeof(eevt));
    eevt.events = events;
    eevt.data.fd = obj.fd;

    if (epoll_ctl(epoll_fd, epoll_op, obj.fd, &eevt) < 0) {
        log_error("pollset_epoll:::add_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    return true;
}

bool pollset_epoll::remove_object(poll_object obj)
{
    auto &ent = pollobjects_map[obj.fd];
    if (ent.fd == -1) {
        log_error("pollset_epoll:::remove_object: object not found obj=%p", obj.ptr);
        return false;
    }
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, obj.fd, nullptr) < 0) {
        log_error("pollset_epoll:::add_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    pollobjects_map[obj.fd] = poll_object();
    return true;
}

const std::vector<poll_object>& pollset_epoll::do_poll(int timeout)
{
    int nevents = epoll_wait(epoll_fd, &eevents[0], (int)eevents.size(), timeout * 1000);
    
    if (nevents < 0 && errno != EAGAIN) {
        log_error("pollset_epoll:::do_poll: epoll_wait: %s", strerror(errno));
        return events;
    }
    
    events.resize(nevents);
    for (int i = 0; i < nevents; i++) {
        struct epoll_event *eevt = &eevents[i];
        events[i] = poll_object(pollobjects_map[eevt->data.fd], eevt->events);
    }
    return events;
}

#endif
