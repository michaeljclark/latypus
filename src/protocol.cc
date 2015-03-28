//
//  protocol.cc
//

#include "plat_os.h"
#include "plat_net.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <deque>
#include <map>
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "connection.h"
#include "connection_tcp.h"
#include "protocol_thread.h"
#include "protocol_engine.h"
#include "protocol_connection.h"

#include "http_common.h"
#include "http_constants.h"
#include "http_parser.h"
#include "http_request.h"
#include "http_response.h"
#include "http_client.h"
#include "http_server.h"


/* protocol_object */

std::string protocol_object::to_string()
{
    char buf[128];
    poll_object_type type = get_poll_type();
    protocol_sock_table *sock_table = protocol_sock::get_table();
    const char *type_name = (size_t)type < sock_table->size() ? sock_table->at((size_t)type)->name.c_str() : "unknown";
    snprintf(buf, sizeof(buf) - 1, "%s:%p", type_name, (void*)this);
    buf[sizeof(buf) - 1] = '\0';
    return buf;
}


/* protocol_sock */

protocol_sock_map* protocol_sock::get_map()
{
    static protocol_sock_map map;
    return &map;
}

protocol_sock_table* protocol_sock::get_table()
{
    static protocol_sock_table table;
    return &table;
}

protocol_sock::protocol_sock(protocol *proto, std::string name, int flags, int type)
    : proto(proto), name(name), flags(flags), type(type)
{
    get_map()->insert(std::pair<protocol_name_pair,protocol_sock*>(protocol_name_pair(proto, name), this));
    get_table()->push_back(this);
    if (protocol::debug) {
        log_debug("protocol_sock     type=0x%08x %s (flags=0x%08x)", type, to_string().c_str(), flags);
    }
}

std::string protocol_sock::to_string() const
{
    return proto ? format_string("%s_sock_%s", proto->name.c_str(), name.c_str()) : name;
}


/* protocol_action */

protocol_action_map* protocol_action::get_map()
{
    static protocol_action_map map;
    return &map;
}

protocol_action_table* protocol_action::get_table()
{
    static protocol_action_table table;
    return &table;
}

protocol_action::protocol_action(protocol *proto, std::string name, protocol_cb *callback, int action)
    : proto(proto), name(name), callback(callback), action(action)
{
    get_map()->insert(std::pair<protocol_name_pair,protocol_action*>(protocol_name_pair(proto, name), this));
    get_table()->push_back(this);
    if (protocol::debug) {
        log_debug("protocol_action action=0x%08x %s", action, to_string().c_str());
    }
}

std::string protocol_action::to_string() const
{
    return proto ? format_string("%s_action_%s", proto->name.c_str(), name.c_str()) : name;
}


/* protocol_mask */

protocol_mask_map* protocol_mask::get_map()
{
    static protocol_mask_map map;
    return &map;
}

protocol_mask_table* protocol_mask::get_table()
{
    static protocol_mask_table table;
    return &table;
}

protocol_mask::protocol_mask(protocol *proto, std::string name, int offset, int mask)
    : proto(proto), name(name), offset(offset), mask(mask)
{
    get_map()->insert(std::pair<protocol_name_pair,protocol_mask*>(protocol_name_pair(proto, name), this));
    get_table()->push_back(this);
    if (protocol::debug) {
        log_debug("protocol_mask     mask=0x%08x %s", mask, to_string().c_str());
    }
}

std::string protocol_mask::to_string() const
{
    return proto ? format_string("%s_mask_%s", proto->name.c_str(), name.c_str()) : name;
}


/* protocol_state */

protocol_state_map* protocol_state::get_map()
{
    static protocol_state_map map;
    return &map;
}

protocol_state_table* protocol_state::get_table()
{
    static protocol_state_table table;
    return &table;
}

protocol_state::protocol_state(protocol *proto, std::string name, protocol_cb *callback, int state)
    : proto(proto), name(name), callback(callback), state(state)
{
    get_map()->insert(std::pair<protocol_name_pair,protocol_state*>(protocol_name_pair(proto, name), this));
    get_table()->push_back(this);
    if (protocol::debug) {
        log_debug("protocol_state   state=0x%08x %s", state, to_string().c_str());
    }
}

std::string protocol_state::to_string() const
{
    return proto ? format_string("%s_connection_%s", proto->name.c_str(), name.c_str()) : name;
}


/* protocol_message */

protocol_message::protocol_message()
    : action(-1), connection_num(-1) {}

protocol_message::protocol_message(int action, int connection_num)
    : action(action), connection_num(connection_num) {}

std::string protocol_message::to_string() const
{
    return format_string("%s connection-%d",
                         protocol_action::get_table()->at(action)->to_string().c_str(),
                         connection_num);
}


/* protocol */

protocol        protocol::proto_none("none");
protocol_sock   protocol::sock_none(nullptr, "none", protocol_sock_none);
protocol_sock   protocol::sock_ipc(nullptr, "ipc", protocol_sock_unix_ipc);
protocol_action protocol::action_none(nullptr, "none");
protocol_state  protocol::state_none(nullptr, "none");

bool protocol::debug = false;

protocol_map* protocol::get_map()
{
    static protocol_map map;
    return &map;
}

protocol_table* protocol::get_table()
{
    static protocol_table table;
    return &table;
}

protocol::protocol(std::string name, int proto) : name(name), proto(proto)
{
    get_map()->insert(std::pair<std::string,protocol*>(name, this));
    get_table()->push_back(this);
    if (protocol::debug) {
        log_debug("protocol         proto=0x%08x %s", proto, name.c_str());
    }
}

std::string protocol::to_string() const { return name; }

void protocol::init()
{
    http_client::get_proto();
    http_server::get_proto();
}
