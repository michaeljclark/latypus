//
//  netd.cc
//
//  http server
//

#include "latypus.h"

struct netd
{
    static cmdline_option options[];
    
    protocol_engine engine;
    
    int             debug_level;
    bool            foreground;
    bool            help_or_error;
    std::string     config_file;
    
    netd();
    bool process_cmdline(int argc, const char *argv[]);
    void run();
};

netd::netd() :
    debug_level(0),
    foreground(false),
    help_or_error(false),
    config_file("config/netd.cfg")
{}

bool netd::process_cmdline(int argc, const char *argv[])
{
    cmdline_option options[] =
    {
        { "-d", "--debug", cmdline_arg_type_none,
            "Increase debugging information",
            [&](std::string s) { ++debug_level; return true; } },
        { "-f", "--foreground", cmdline_arg_type_none,
            "Run as a foreground process",
            [&](std::string s) { return (foreground = true); } },
        { "-h", "--help", cmdline_arg_type_none,
            "Show help",
            [&](std::string s) { return (help_or_error = true); } },
        { "-c", "--config", cmdline_arg_type_string,
            "Configuration file",
            [&](std::string s) { config_file = s; return true; } },
        { nullptr, nullptr, cmdline_arg_type_none,   nullptr, nullptr }
    };
    
    auto result = cmdline_option::process_options(options, argc, argv);
    if (!result.second) {
        help_or_error = true;
    } else if (result.first.size() != 0) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        help_or_error = true;
    }
    if (help_or_error) {
        fprintf(stderr, "usage: %s\n", argv[0]);
        cmdline_option::print_options(options);
        return false;
    }
    
    
    return true;
}

void netd::run()
{
    // enable debug messages
    if (debug_level >= 1) {
        engine.debug_mask = (protocol_debug_engine |
                             protocol_debug_thread);
    }
    if (debug_level >= 2) {
        engine.debug_mask = protocol_debug_all;
    }
    
    // read config
    engine.read_config(config_file);

    // daemonize
    if (!foreground) {
        os::daemonize(engine.cfg->pid_file, engine.cfg->error_log);
    }
    
    // run server
    engine.run();
    engine.join();
}


/* main */

int main(int argc, const char * argv[])
{
    netd server;
    
    // parse command line arguments
    if (!server.process_cmdline(argc, argv)) {
        exit(1);
    }
    
    // start server
    server.run();
    
    return 0;
}
