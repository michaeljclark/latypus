#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <map>

#include "io.h"
#include "log.h"
#include "socket.h"
#include "config_parser.h"
#include "config.h"

int main(int argc, const char * argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <configfile>\n", argv[0]);
        exit(1);
    }
    
    config cfg;
    cfg.read(argv[1]);
    
    std::cout << cfg.to_string();

    return 0;
}
