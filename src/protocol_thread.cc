//
//  protocol_thread.cc
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
#include <unordered_map>
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
#include "pollset_poll.h"
#include "pollset_epoll.h"
#include "pollset_kqueue.h"
#include "protocol.h"
#include "connection.h"
#include "connection.h"
#include "protocol_thread.h"
#include "protocol_engine.h"


/* protocol_thread */

protocol_thread::protocol_thread(protocol_engine *engine, int thread_mask)
  : engine(engine),
    thread_mask(thread_mask),
    notify(engine->cfg->ipc_buffer_size),
    pollset(new pollset_platform_type()),
    running(true),
    current_time(0),
    timeout_check(0),
    dns(new resolver),
    thread(&protocol_thread::mainloop, this)
{}

protocol_thread::~protocol_thread()
{}

int protocol_thread::string_to_thread_mask(std::string str)
{
    protocol_map* proto_map = protocol::get_map();
    int thread_mask = 0;
    size_t current;
    size_t next = -1;
    size_t colon = -1;
    do {
        current = next + 1;
        next = str.find_first_of(",", current);
        std::string proto_mask_name = str.substr(current, next - current);
        colon = proto_mask_name.find_first_of("/");
        if (colon == std::string::npos) {
            log_fatal_exit("invalid server thread format <protocol/mask>: %s", proto_mask_name.c_str());
        }
        std::string proto_name = proto_mask_name.substr(0, colon);
        std::string mask_name =proto_mask_name.substr(colon + 1);
        auto pi = proto_map->find(proto_name);
        if (pi == proto_map->end()) {
            log_fatal_exit("unknown protocol name: %s", proto_name.c_str());
        }
        protocol *proto = pi->second;
        int found = 0;
        for (const protocol_mask *ent : *protocol_mask::get_table()) {
            if (ent->name == mask_name && proto == ent->proto) {
                found = ent->mask;
                break;
            }
            ent++;
        }
        if (found) {
            thread_mask |= found;
        } else {
            log_fatal_exit("unknown server thread mask: %s for protocol: %s", mask_name.c_str(), proto_name.c_str());
        }
    } while (next != std::string::npos);
    
    return thread_mask;
}

std::string protocol_thread::thread_mask_to_string(int thread_mask)
{
    std::stringstream ss;
    for (const protocol_mask *ent : *protocol_mask::get_table()) {
        if (thread_mask & ent->mask) {
            if (ss.str().length() > 0) ss << ",";
            ss << ent->proto->name << "/" << ent->name;
        }
    }
    return ss.str();
}

protocol_table protocol_thread::thread_mask_to_protocols(int thread_mask)
{
    protocol_table proto_list;
    for (auto proto_mask : *protocol_mask::get_table()) {
        if (thread_mask & proto_mask->mask) {
            if (std::find(proto_list.begin(), proto_list.end(), proto_mask->proto) == proto_list.end()) {
                proto_list.push_back(proto_mask->proto);
            }
        }
    }
    return proto_list;
}

void protocol_thread::set_thread_name(std::string name)
{
#if defined (__FreeBSD__)
    pthread_set_name_np(pthread_self(), name.c_str());
#elif defined (__linux__)
    pthread_setname_np(pthread_self(), name.c_str());
#elif defined (__APPLE__)
    pthread_setname_np(name.c_str());
#endif
}

protocol_thread_state* protocol_thread::get_thread_state(protocol *proto)
{
    for (auto &state : state_list) {
        if (state->get_proto() == proto) return state.get();
    }
    auto state = proto->create_thread_state();
    if (state) {
        state_list.push_back(protocol_thread_state_ptr(state));
    }
    return state;
}

protocol_engine_delegate* protocol_thread::get_engine_delegate() const { return engine; }
time_t protocol_thread::get_current_time() const { return current_time; }
config_ptr protocol_thread::get_config() const { return engine->cfg; }
pollset_ptr protocol_thread::get_pollset() const { return pollset; }
resolver_ptr protocol_thread::get_resolver() const { return dns; }
std::thread::id protocol_thread::get_thread_id() const { return thread.get_id(); }
std::string protocol_thread::get_thread_string() const { return thread_mask_to_string(thread_mask); }
int protocol_thread::get_thread_mask() const { return thread_mask; }
int protocol_thread::get_debug_mask() const { return engine->debug_mask; }

protocol_thread_delegate* protocol_thread::choose_thread(int thread_mask)
{
    if (this->thread_mask & thread_mask) return this;
    return engine->choose_thread(thread_mask);
}

void protocol_thread::send_message(protocol_thread_delegate *to_thread, protocol_message msg)
{
    auto dest_thread = static_cast<protocol_thread*>(to_thread);
    if (this == to_thread) {
        (*protocol_action::get_table())[msg.action]->proto->handle_message(this, msg);
    } else {
        // TODO - change to lock free message queues and use notify socket for wakeup
        io_result result = dest_thread->notify.send_message(unix_socketpair_client, &msg, sizeof(msg));
        if (result.has_error()) {
            if (result.error().errcode != EAGAIN && result.error().errcode != ENOBUFS) {
                log_error("protocol_thread::send_message: %s", result.error_string().c_str());
            } else {
                queue_message(dest_thread, msg);
            }
        } else if (result.size() != sizeof(msg)) {
            log_error("protocol_thread::send_message: short write");
        }
    }
}

void protocol_thread::queue_message(protocol_thread_delegate *to_thread, protocol_message msg)
{
    auto dest_thread = static_cast<protocol_thread*>(to_thread);
    dest_thread->message_lock.lock();
    dest_thread->message_queue.push_back(msg);
    dest_thread->message_lock.unlock();
}

void protocol_thread::add_events(protocol_object *obj, int events)
{
    pollset->add_object(poll_object(obj->get_poll_type(), obj, obj->get_poll_fd()), events);
}

void protocol_thread::remove_events(protocol_object *obj)
{
    pollset->remove_object(poll_object(obj->get_poll_type(), obj, obj->get_poll_fd()));
}

void protocol_thread::receive_message()
{
    protocol_message msg;
    io_result result = notify.recv_message(unix_socketpair_owner, &msg, sizeof(msg));
    if (result.has_error()) {
        log_error("protocol_thread::receive_message: %s", result.error_string().c_str());
    } else if (result.size() != sizeof(msg)) {
        log_error("protocol_thread::receive_message: short read");
    } else if (msg.action == protocol::action_none.action) {
        // wake up
    } else {
        (*protocol_action::get_table())[msg.action]->proto->handle_message(this, msg);
    }
    message_lock.lock();
    while (message_queue.begin() != message_queue.end()) {
        protocol_message msg = message_queue.front();
        message_queue.pop_front();
        (*protocol_action::get_table())[msg.action]->proto->handle_message(this, msg);
    }
    message_lock.unlock();
}

void protocol_thread::mainloop()
{
    if (engine->debug_mask & protocol_debug_thread) {
        log_debug("%90s:%p: started", get_thread_string().c_str(), get_thread_id());
    }
    
    // block signals
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        log_fatal_exit("protocol_thread::mainloop: can't set thread signal mask: %s", strerror(errno));
    }
    
    // add notify socket pair to pollset
    pollset->add_object(poll_object(protocol::sock_ipc.type, &notify, notify.owner.get_fd()), poll_event_in);
    
    // run thread init for each protocol handled by this thread
    // TODO - handle bad_alloc exceptions
    for (auto proto : thread_mask_to_protocols(thread_mask)) {
        proto->thread_init(this);
    }
    
    // set thread name
    set_thread_name(get_thread_string());

    int timeout_min = (std::min)(get_config()->connection_timeout, get_config()->keepalive_timeout);

    const protocol_sock_table *proto_sock_table = protocol_sock::get_table();

    // poll
    while (running) {
        const std::vector<poll_object> &events = pollset->do_poll(timeout_min);
        current_time = time(nullptr);
        for (auto obj : events) {
            if (engine->debug_mask & protocol_debug_event) {
                // TODO eventually make pollset use protocol_sock to print socket name
                log_debug("%90s:%p: %s",
                          get_thread_string().c_str(), get_thread_id(), obj.to_string().c_str());
            }
            if (obj.type == protocol::sock_ipc.type) {
                receive_message();
            } else {
                if (obj.type < proto_sock_table->size()) {
                    const protocol_sock *proto_sock = (*proto_sock_table)[obj.type];
                    if (proto_sock->proto) {
                        // TODO - handle TLS connections
                        if (proto_sock->flags & protocol_sock_tcp_listen) {
                            proto_sock->proto->handle_accept(this, proto_sock, obj.fd);
                        } else if (proto_sock->flags & protocol_sock_tcp_connection) {
                            proto_sock->proto->handle_connection(this, static_cast<protocol_object*>(obj.ptr), obj.event_mask);
                        } else {
                            log_error("%90s:%p: unknown flags: %s",
                                      get_thread_string().c_str(), get_thread_id(), obj.to_string().c_str());
                        }
                    } else {
                        log_error("%90s:%p: missing protocol: %s",
                                  get_thread_string().c_str(), get_thread_id(), obj.to_string().c_str());
                    }
                } else {
                    log_error("%90s:%p: invalid socket type: %s",
                              get_thread_string().c_str(), get_thread_id(), obj.to_string().c_str());
                }
            }
        }
        if (current_time - timeout_check > timeout_min) {
            timeout_check = current_time;
            auto pollobjects_copy = pollset->get_objects();
            for (auto obj : pollobjects_copy) {
                if (obj.type < proto_sock_table->size()) {
                    const protocol_sock *proto_sock = (*proto_sock_table)[obj.type];
                    if (proto_sock->proto) {
                        // TODO - handle TLS connections
                        if (proto_sock->flags & protocol_sock_tcp_connection) {
                            proto_sock->proto->timeout_connection(this, static_cast<protocol_object*>(obj.ptr));
                        }
                    }
                } else {
                    log_error("%90s:%p: invalid socket type: %s",
                              get_thread_string().c_str(), get_thread_id(), obj.to_string().c_str());
                }
            }
        }
    }
    
    if (engine->debug_mask & protocol_debug_thread) {
        log_debug("%90s:%p: finished", get_thread_string().c_str(), get_thread_id());
    }
}
