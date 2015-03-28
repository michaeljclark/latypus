//
//  pollset_poll.cc
//

#include "plat_poll.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "io.h"
#include "log.h"
#include "socket.h"
#include "pollset.h"
#include "pollset_poll.h"


pollset_poll::pollset_poll() {}

const std::vector<poll_object>& pollset_poll::get_objects() { return pollobjects; }

bool pollset_poll::add_object(poll_object obj, int events)
{
    // TODO - add option to prealocate memory and/or handle bad_alloc
    size_t pi;
    std::vector<poll_object>::iterator oi;
    if ((oi = std::find(pollobjects.begin(), pollobjects.end(), obj)) != pollobjects.end()) {
        pi = oi - pollobjects.begin();
    } else {
        pi = pollobjects.size();
        pollobjects.push_back(obj);
        pollfds.resize(pi + 1);
        pollfds[pi].fd = obj.fd;
    }
    pollfds[pi].events = events;
    pollfds[pi].revents = 0;
    return true;
}

bool pollset_poll::remove_object(poll_object obj)
{
    std::vector<poll_object>::iterator oi;
    if ((oi = std::find(pollobjects.begin(), pollobjects.end(), obj)) == pollobjects.end()) {
        log_error("pollset_poll::remove_object: object not found obj=%p", obj.ptr);
        return false;
    }
    size_t pi = oi - pollobjects.begin();
    pollfds.erase(pollfds.begin() + pi, pollfds.begin() + pi + 1);
    pollobjects.erase(pollobjects.begin() + pi, pollobjects.begin() + pi + 1);
    return true;
}

const std::vector<poll_object>& pollset_poll::do_poll(int timeout)
{
    events.resize(0);
    
    unsigned int pollset_size = (unsigned int)pollobjects.size();
    int ret = poll(&pollfds[0], pollset_size, timeout * 1000);
    
    if (ret < 0 && errno != EAGAIN) {
        log_error("pollset_poll:::do_poll: poll: %s", strerror(errno));
        return events;
    }
    
    events.reserve(pollset_size);
    for (size_t pi = 0; pi < pollset_size; pi++) {
        if (pollfds[pi].revents) {
            events.push_back(poll_object(pollobjects[pi], pollfds[pi]));
        }
    }
    return events;
}
