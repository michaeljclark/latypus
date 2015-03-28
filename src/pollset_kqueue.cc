//
//  pollset_kqueue.cc
//

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__)

#include "plat_poll.h"

#include <cassert>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "io.h"
#include "log.h"
#include "socket.h"
#include "pollset.h"
#include "pollset_kqueue.h"

const int pollset_kqueue::max_events = 48;

pollset_kqueue::pollset_kqueue()
{
    kevent_fd = kqueue();
    kevents.resize(max_events);
}

pollset_kqueue::~pollset_kqueue()
{
    close(kevent_fd);
}

const std::vector<poll_object>& pollset_kqueue::get_objects() { return pollobjects; }

bool pollset_kqueue::add_object(poll_object obj, int events)
{
    // TODO - add option to prealocate memory and/or handle bad_alloc
    size_t pi;
    std::vector<poll_object>::iterator oi;
    if ((oi = std::find(pollobjects.begin(), pollobjects.end(), obj)) != pollobjects.end()) {
        pi = oi - pollobjects.begin();
    } else {
        pi = pollobjects.size();
        pollobjects.push_back(obj);
        pollfilter.push_back(0);
    }
    struct kevent kevt;
    short newfilter = 0;
    if (events & poll_event_in) newfilter |= EVFILT_READ;
    if (events & poll_event_out) newfilter |= EVFILT_WRITE;
    EV_SET(&kevt, obj.fd, newfilter, EV_ADD, 0, 0, (void*)(unsigned long)obj.fd);
    if (kevent(kevent_fd, &kevt, 1, NULL, 0, NULL) < 0) {
        log_error("pollset_kqueue:::add_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    pollfilter[pi] = newfilter;
    return true;
}

bool pollset_kqueue::remove_object(poll_object obj)
{
    std::vector<poll_object>::iterator oi;
    if ((oi = std::find(pollobjects.begin(), pollobjects.end(), obj)) == pollobjects.end()) {
        log_debug("pollset_kqueue:::remove_object: object not found obj=%p", obj.ptr);
        return false;
    }
    size_t pi = oi - pollobjects.begin();
    struct kevent kevt;
    EV_SET(&kevt, obj.fd, pollfilter[pi], EV_DELETE, 0, 0, NULL);
    if (kevent(kevent_fd, &kevt, 1, NULL, 0, NULL) < 0) {
        log_error("pollset_kqueue:::remove_object: obj=%p: %s", obj.ptr, strerror(errno));
        return false;
    }
    pollfilter.erase(pollfilter.begin() + pi, pollfilter.begin() + pi + 1);
    pollobjects.erase(pollobjects.begin() + pi, pollobjects.begin() + pi + 1);
    return true;
}

const std::vector<poll_object>& pollset_kqueue::do_poll(int timeout)
{
    struct timespec ts;
    ts.tv_sec = timeout;
    ts.tv_nsec = 0;

    int nevents = kevent(kevent_fd, NULL, 0, &kevents[0], (int)kevents.size(), &ts);    
    if (nevents < 0 && errno != EAGAIN) {
        log_error("pollset_kqueue:::do_poll: kevent: %s", strerror(errno));
        return events;
    }
    
    events.resize(0);
    events.reserve(max_events);
    for (int ki = 0; ki < nevents; ki++) {
        struct kevent *kevt = &kevents[ki];
        auto oi = std::find_if(pollobjects.begin(), pollobjects.end(),
                               [=] (const poll_object &obj) { return obj.fd == (int)kevt->ident; });
        if (oi != pollobjects.end()) {
            short revents = 0;
            if (kevt->flags & EV_EOF) revents |= poll_event_hup;
            if (kevt->flags & EV_ERROR) revents |= poll_event_err;
            if (kevt->filter & EVFILT_READ) revents |= poll_event_in;
            if (kevt->filter & EVFILT_WRITE) revents |= poll_event_out;
            events.push_back(poll_object(*oi, revents));
        }
    }
    return events;
}

#endif
