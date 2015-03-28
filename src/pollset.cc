//
//  pollset.cc
//

#include "plat_poll.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <functional>
#include <thread>
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <deque>
#include <map>

#include "io.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "pollset_poll.h"
#include "pollset_kqueue.h"
#include "protocol.h"


/* pollfds */

std::string poll_object::to_string()
{
    char buf[128];
    protocol_sock_table *sock_table = protocol_sock::get_table();
    const char *type_name = type < sock_table->size() ? sock_table->at(type)->name.c_str() : "unknown";
    if (event_mask) {
        snprintf(buf, sizeof(buf) - 1, "%s:%p: event_fd:%05d event_mask:0x%04x", type_name, ptr, fd, event_mask);
    } else {
        snprintf(buf, sizeof(buf) - 1, "%s:%p: event_fd:%05d", type_name, ptr, fd);
    }

    buf[sizeof(buf) - 1] = '\0';
    return buf;
}

/* pollset */

pollset::~pollset() {}
