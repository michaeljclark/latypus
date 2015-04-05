//
//  os.h
//

#ifndef os_h
#define os_h

struct os
{
    static void daemonize(std::string pid_file, std::string log_file);
};

#endif
