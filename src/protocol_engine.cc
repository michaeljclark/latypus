//
//  protocol_engine.cc
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

#include "os.h"
#include "io.h"
#include "url.h"
#include "log.h"
#include "socket.h"
#include "socket_unix.h"
#include "resolver.h"
#include "config_parser.h"
#include "config.h"
#include "pollset.h"
#include "protocol.h"
#include "protocol_thread.h"
#include "protocol_engine.h"


/* protocol_engine */

protocol_config_factory_map protocol_engine::config_factory_map;
std::vector<protocol_engine*> protocol_engine::engine_list;
std::mutex protocol_engine::engine_lock;

protocol_engine::protocol_engine() : debug_mask(0)
{
    protocol::init();
    
    // block signals before taking engine lock so we don't deadlock in signal handlers
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        log_fatal_exit("protocol_engine: can't set thread signal mask: %s", strerror(errno));
    }
    
    // take engine lock
    engine_lock.lock();
    
    // set signal handlers if this is the first engine
    if (engine_list.size() == 0) {
        sigset_t sigpipe_set;
        sigemptyset(&sigpipe_set);
        sigaddset(&sigpipe_set, SIGPIPE);
        sigprocmask(SIG_BLOCK, &sigpipe_set, nullptr);

        struct sigaction sigaction_handler;
        memset(&sigaction_handler, 0, sizeof(sigaction_handler));
        sigaction_handler.sa_sigaction = signal_handler;
        sigaction_handler.sa_flags = SA_SIGINFO;
        sigaction(SIGTERM, &sigaction_handler, nullptr);
        sigaction(SIGINT, &sigaction_handler, nullptr);
        sigaction(SIGHUP, &sigaction_handler, nullptr);
    }

    // add engine to the list
    engine_list.push_back(this);

    // release engine lock
    engine_lock.unlock();

    // unblock signals
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
        log_fatal_exit("protocol_engine: can't set thread signal mask: %s", strerror(errno));
    }
}

protocol_engine::~protocol_engine()
{
    engine_lock.lock();
    auto ei = std::find(engine_list.begin(), engine_list.end(), this);
    if (ei != engine_list.end()) {
        engine_list.erase(ei);
    }
    engine_lock.unlock();
}

void protocol_engine::signal_handler(int signum, siginfo_t *info, void *)
{
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            for (auto engine : engine_list) {
                engine->stop();
            }
            break;
        default:
            break;
    }
}

void protocol_engine::protocol_config_init(config_ptr cfg)
{
    // initialize protocol specific config
    for (auto proto : *protocol::get_table()) {
        protocol_config_ptr proto_conf = proto->make_protocol_config();
        if (proto_conf) {
            cfg->proto_conf_map.insert(std::pair<const protocol*,protocol_config_ptr>(proto, proto_conf));
        }
    }
}

config_ptr protocol_engine::default_config(protocol* proto)
{
    cfg = config_ptr(new config());
    protocol_config_init(cfg);
    proto->make_default_config(cfg);
    return cfg;
}

void protocol_engine::read_config(std::string config_file)
{
    cfg = config_ptr(new config());
    protocol_config_init(cfg);
    cfg->read(config_file);
}

void protocol_engine::run()
{
    if (debug_mask & protocol_debug_engine) {
        log_debug("protocol_engine: starting up");
    }
    
    // run engine init for all protocols handled by this engine
    for (auto proto : protocol_thread::thread_mask_to_protocols(get_all_threads_mask())) {
        proto->engine_init(this);
    }
    
    // set os_group
    if (cfg->os_group.length() > 0) {
        os::set_group(cfg->os_group);
    }

    // set os_user
    if (cfg->os_user.length() > 0) {
        os::set_user(cfg->os_user);
    }

    // create threads for all protocols handled by this engine
    for (int thread_mask : get_thread_masks()) {
        add_thread(new protocol_thread(this, thread_mask));
    }
}

void protocol_engine::stop()
{
    threads_cond.notify_one();
}

void protocol_engine::join()
{
    // wait on condition
    {
        std::unique_lock<std::mutex> lock(threads_mutex);
        threads_cond.wait(lock);
        if (debug_mask & protocol_debug_engine) {
            log_debug("protocol_engine: shutting down");
        }
        for (auto &thread : threads_all) {
            thread->running = false;
            protocol_message msg(protocol::action_none.action, 0);
            thread->notify.send_message(unix_socketpair_client, &msg, sizeof(msg));
        }
    }
    
    // join threads
    for (auto &thread : threads_all) {
        thread->thread.join();
    }
    
    // run engine shutdown for all protocols handled by this engine
    for (auto proto : protocol_thread::thread_mask_to_protocols(get_all_threads_mask())) {
        proto->engine_shutdown(this);
    }
}

std::vector<int> protocol_engine::get_thread_masks()
{
    // create thread mask list
    std::vector<int> thread_masks;
    for (auto thread : cfg->proto_threads) {
        for (size_t i = 0; i < thread.second; i++) {
            thread_masks.push_back(protocol_thread::string_to_thread_mask(thread.first));
        }
    }
    return thread_masks;
}

int protocol_engine::get_all_threads_mask()
{
    // create thread mask list
    int all_thread_masks = 0;
    for (auto thread : cfg->proto_threads) {
        for (size_t i = 0; i < thread.second; i++) {
            all_thread_masks |= protocol_thread::string_to_thread_mask(thread.first);
        }
    }
    return all_thread_masks;
}

protocol_engine_state* protocol_engine::get_engine_state(protocol *proto)
{
    for (auto &state : state_list) {
        if (state->get_proto() == proto) return state.get();
    }
    auto state = proto->create_engine_state(cfg);
    if (state) {
        state_list.push_back(protocol_engine_state_ptr(state));
    }
    return state;
 }

config_ptr protocol_engine::get_config() const { return cfg; }

void protocol_engine::add_thread(protocol_thread *thread)
{
    threads_mutex.lock();
    threads_all.push_back(protocol_thread_ptr(thread));
    for (const protocol_mask *ent : *protocol_mask::get_table()) {
        if (thread->thread_mask & ent->mask) {
            auto tmi = threads_map.find(ent->mask);
            if (tmi == threads_map.end()) {
                tmi = threads_map.insert(std::pair<int,protocol_thread_list>(ent->mask, protocol_thread_list())).first;
            }
            (*tmi).second.push_back(thread);
            if (threads_next.find(ent->mask) == threads_next.end()) {
                threads_next.insert(std::pair<int,size_t>(ent->mask, 0));
            }
        }
        ent++;
    }
    threads_mutex.unlock();
}

protocol_thread* protocol_engine::choose_thread(int mask)
{
    protocol_thread *chosen_thread = nullptr;
    threads_mutex.lock();
    const auto &tmi = threads_map.find(mask);
    const auto &nti = threads_next.find(mask);
    if (tmi == threads_map.end() || nti == threads_next.end()) {
        threads_mutex.unlock();
        return nullptr;
    }
    protocol_thread_list &thread_list = (*tmi).second;
    size_t &thread_next = (*nti).second;
    chosen_thread = thread_list.at(thread_next);
    if (++thread_next == thread_list.size()) {
        thread_next = 0;
    }
    threads_mutex.unlock();
    return chosen_thread;
}
