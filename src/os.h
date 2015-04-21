//
//  os.h
//

#ifndef os_h
#define os_h

struct os
{
    static void daemonize(std::string pid_file, std::string log_file);
    static void set_group(std::string os_group);
    static void set_user(std::string os_user);
};

#endif
