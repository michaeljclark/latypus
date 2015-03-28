//
//  netc.cc
//

#include "latypus.h"

/* netc */

#define NUM_REQUESTS_DEFAULT        1
#define KEEPALIVE_REQUESTS_DEFAULT  0

#define expand(s) quote(s)
#define quote(s) #s

using namespace std::chrono;

struct netc
{
    static cmdline_option options[];
    
    protocol_engine engine;
    
    std::atomic<int>    processed_requests;
    std::atomic<size_t> bytes_transfered;
    int                 client_connections;
    int                 connection_timeout;
    int                 keepalive_requests;
    int                 keepalive_timeout;
    int                 header_buffer_size;
    int                 io_buffer_size;
    int                 num_requests;
    int                 num_threads;
    std::string         output_file;
    bool                remote_name;
    bool                help_or_error;
    int                 debug_level;
    std::string         bench_url;
    
    netc();
    bool process_cmdline(int argc, const char *argv[]);
    void run();
};

struct netc_client_handler_file : http_client_handler_file
{
    struct netc *client;
    netc_client_handler_file(struct netc *client, int fd) : http_client_handler_file(fd), client(client) {}
    bool end_request();
};

bool netc_client_handler_file::end_request()
{
    http_client_handler_file::end_request();
    client->processed_requests++;
    client->bytes_transfered += total_read;
    if (client->processed_requests == client->num_requests) {
        client->engine.stop();
    }    
    return true;
}

netc::netc() :
    processed_requests(0),
    bytes_transfered(0),
    client_connections(CLIENT_CONNECTIONS_DEFAULT),
    connection_timeout(CONNETION_TIMEOUT_DEFAULT),
    keepalive_requests(KEEPALIVE_REQUESTS_DEFAULT),
    keepalive_timeout(KEEPALIVE_TIMEOUT_DEFAULT),
    header_buffer_size(HEADER_BUFFER_SIZE_DEFAULT),
    io_buffer_size(IO_BUFFER_SIZE_DEFAULT),
    num_requests(NUM_REQUESTS_DEFAULT),
    num_threads(std::thread::hardware_concurrency()),
    output_file(),
    remote_name(false),
    help_or_error(false),
    debug_level(0)
{}

bool netc::process_cmdline(int argc, const char *argv[])
{
    cmdline_option options[] =
    {
        { "-c", "--client-connections", cmdline_arg_type_int,
            "Maximum number of connections (default " expand(CLIENT_CONNECTIONS_DEFAULT) ")",
            [&](std::string s) { client_connections = atoi(s.c_str()); return true; } },
        { "-C", "--connection-timeout", cmdline_arg_type_int,
            "Connection timeout seconds (default " expand(CONNETION_TIMEOUT_DEFAULT) ")",
            [&](std::string s) { connection_timeout = atoi(s.c_str()); return true; } },
        { "-d", "--debug", cmdline_arg_type_none,
            "Increase debugging information",
            [&](std::string s) { ++debug_level; return true; } },
        { "-h", "--help", cmdline_arg_type_none,
            "Show help",
            [&](std::string s) { return (help_or_error = true); } },
        { "-k", "--keepalive-requests", cmdline_arg_type_int,
            "Keepalive requests per connection (default " expand(KEEPALIVE_REQUESTS_DEFAULT) ")",
            [&](std::string s) { keepalive_requests = atoi(s.c_str()); return true; } },
        { "-K", "--keepalive-timeout", cmdline_arg_type_int,
            "Keepalive timeout seconds (default " expand(KEEPALIVE_TIMEOUT_DEFAULT) ")",
            [&](std::string s) { keepalive_timeout = atoi(s.c_str()); return true; } },
        { "-H", "--header-buffer-size", cmdline_arg_type_int,
            "Header Buffer Size (default " expand(HEADER_BUFFER_SIZE_DEFAULT) ")",
            [&](std::string s) { io_buffer_size = atoi(s.c_str()); return true; } },
        { "-B", "--io-buffer-size", cmdline_arg_type_int,
            "Input Ouput Buffer Size (default " expand(IO_BUFFER_SIZE_DEFAULT) ")",
            [&](std::string s) { header_buffer_size = atoi(s.c_str()); return true; } },
        { "-t", "--num-threads", cmdline_arg_type_int,
            "Number of threads (default hardware concurrency)",
            [&](std::string s) { num_threads = atoi(s.c_str()); return true; } },
        { "-o", "--output", cmdline_arg_type_string,
            "Output File",
            [&](std::string s) { output_file = s.c_str(); return true; } },
        { "-O", "--remote-name", cmdline_arg_type_none,
            "Output File",
            [&](std::string s) { return (remote_name = true); } },
        { nullptr, nullptr, cmdline_arg_type_none, nullptr, nullptr }
    };
    
    auto result = cmdline_option::process_options(options, argc, argv);
    if (!result.second) {
        help_or_error = true;
    } else if (result.first.size() != 1) {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        help_or_error = true;
    }
    if (help_or_error) {
        fprintf(stderr, "usage: %s [options] [http[s]://]hostname[:port]/path\n", argv[0]);
        cmdline_option::print_options(options);
        return false;
    }
    bench_url = result.first[0];
    return true;
}

void netc::run()
{
    // setup default config
    engine.cfg = std::make_shared<config>();
    engine.cfg->client_connections = client_connections;
    engine.cfg->connection_timeout = connection_timeout;
    engine.cfg->keepalive_timeout = keepalive_timeout;
    engine.cfg->header_buffer_size = header_buffer_size;
    engine.cfg->io_buffer_size = io_buffer_size;
    engine.cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_client/connect", 1));
    engine.cfg->proto_threads.push_back(std::pair<std::string,size_t>("http_client/processor,http_client/keepalive", num_threads));
    
    // enable debug messages
    if (debug_level >= 1) {
        engine.debug_mask = (protocol_debug_engine |
                             protocol_debug_thread);
    }
    if (debug_level >= 2) {
        engine.debug_mask = (protocol_debug_event |
                             protocol_debug_socket |
                             protocol_debug_headers |
                             protocol_debug_message |
                             protocol_debug_handler |
                             protocol_debug_timeout);
    }
    
    // parse benchmark url
    url_ptr req_url(new url(bench_url));
    if (!req_url->valid) {
        fprintf(stderr, "error: invalid url: %s\n", bench_url.c_str());
        exit(1);
    }
    
    if (remote_name) {
        size_t last_slash = bench_url.find_last_of('/');
        if (last_slash != std::string::npos) {
            output_file = bench_url.substr(last_slash + 1);
        }
    }
    
    // open output file or stdout if not specified
    int out_fd;
    if (output_file.length() > 0) {
        out_fd = open(output_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0666);
        if (out_fd < 0) {
            log_fatal_exit("can't open %s: %s", output_file.c_str(), strerror(errno));
        }
    } else {
        out_fd = fileno(stdout);
    }
        
    // run client
    const auto t1 = high_resolution_clock::now();
    engine.run();
    auto handler = std::make_shared<netc_client_handler_file>(this, out_fd);
    auto request = std::make_shared<http_client_request>(HTTPMethodGET, req_url, handler);
    http_client::submit_request(&engine, request, keepalive_requests);
    engine.join();
    const auto t2 = high_resolution_clock::now();
    double secs = duration_cast<microseconds>(t2 - t1).count() / 1000000.0;
    printf("%9.6lf secs,  %ld bytes transferred,  %lf MB/sec\n",
           secs,
           bytes_transfered.load(),
           bytes_transfered.load() / secs / (1 << 20));

    // close output
    if (output_file.length() > 0) {
        close(out_fd);
    }
}


/* main */

int main(int argc, const char *argv[])
{
    http_constants::init();
    
    netc bench;
    
    // parse command line arguments
    if (!bench.process_cmdline(argc, argv)) {
        exit(1);
    }
    
    // start benchmark client
    bench.run();
    
    return 0;
}
