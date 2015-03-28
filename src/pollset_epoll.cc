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
}

pollset_epoll::~pollset_epoll()
{
    close(epoll_fd);
}

const std::vector<poll_object>& pollset_epoll::get_objects()
{
    size_t i = 0;
    pollobjects.resize(pollobjects_map.size());
    for (auto &ent : pollobjects_map) {
        pollobjects[i++] = ent.second;
    }
    return pollobjects;
}

bool pollset_epoll::add_object(poll_object obj, int events)
{
    // TODO - add option to prealocate memory and/or handle bad_alloc
    int epoll_op;
    auto oi = pollobjects_map.find(obj.fd);
    if (oi != pollobjects_map.end()) {
        epoll_op = EPOLL_CTL_MOD;
    } else {
        auto ci = pollobjects_map.emplace(std::make_pair(obj.fd, obj));
        if (!ci.second) {
            log_error("pollset_epoll:::add_object: obj=%p: insert failed", obj.ptr);
            return false;
        }
        epoll_op = EPOLL_CTL_ADD;
    }

    short newfilter = 0;
    if (events & poll_event_in) newfilter |= EPOLLIN;
    if (events & poll_event_out) newfilter |= EPOLLOUT;
    
    struct epoll_event eevt;
    memset(&eevt, 0, sizeof(eevt));
    eevt.events = newfilter;
    eevt.data.fd = obj.fd;

    if (epoll_ctl(epoll_fd, epoll_op, obj.fd, &eevt) < 0) {
        log_error("pollset_epoll:::add_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    return true;
}

bool pollset_epoll::remove_object(poll_object obj)
{
    auto oi = pollobjects_map.find(obj.fd);
    if (oi == pollobjects_map.end()) {
        log_error("pollset_epoll:::remove_object: object not found obj=%p", obj.ptr);
        return false;
    }
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, obj.fd, nullptr) < 0) {
        log_error("pollset_epoll:::add_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    pollobjects_map.erase(oi);
    return true;
}

const std::vector<poll_object>& pollset_epoll::do_poll(int timeout)
{
    events.resize(0);

    int nevents = epoll_wait(epoll_fd, &eevents[0], (int)eevents.size(), timeout * 1000);
    
    if (nevents < 0 && errno != EAGAIN) {
        log_error("pollset_epoll:::do_poll: epoll_wait: %s", strerror(errno));
        return events;
    }
    
    events.reserve(max_events);
    for (int i = 0; i < nevents; i++) {
        struct epoll_event *eevt = &eevents[i];
        auto oi = pollobjects_map.find(eevt->data.fd);
        if (oi == pollobjects_map.end()) continue;
        short revents = 0;
        if (eevt->events & EPOLLHUP) revents |= poll_event_hup;
        if (eevt->events & EPOLLERR) revents |= poll_event_err;
        if (eevt->events & EPOLLIN) revents |= poll_event_in;
        if (eevt->events & EPOLLOUT) revents |= poll_event_out;
        events.push_back(poll_object((*oi).second, revents));
    }
    return events;
}

#endif
