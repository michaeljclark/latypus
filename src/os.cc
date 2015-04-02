//
//  daemon.h
//

#include "plat_os.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>

#include "log.h"
#include "os.h"

static std::string latypus_pid_file;

void unlink_pidfile()
{
    unlink(latypus_pid_file.c_str());
}

void os::daemonize(std::string pid_file, std::string log_file)
{
    latypus_pid_file = pid_file;
    
    // exit if the pid file already exists
    struct stat statbuf;
    int ret = stat(pid_file.c_str(), &statbuf);
    if (ret >= 0 && errno != ENOENT) {
        log_fatal_exit("pid file already exists: %s", pid_file.c_str());
    }
    
    // open log_file
    int log_fd = open(log_file.c_str(), O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (log_fd < 0) {
        log_fatal_exit("error opening log file: %s", pid_file.c_str());
    }

    // fork a new process
    pid_t pid = fork();
    if (pid < 0) {
        log_fatal_exit("fork: %s", strerror(errno));
    }
    if (pid > 0) {
        // write pid to pid_file
        int pid_fd = open(pid_file.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (pid_fd < 0) {
            log_fatal_exit("error opening pid file: %s", pid_file.c_str());
        }
        char pid_buf[16];
        snprintf(pid_buf, sizeof(pid_buf), "%d\n", pid);
        if (write(pid_fd, pid_buf, strlen(pid_buf)) < 0) {
            log_fatal_exit("error writing pid file: %s", pid_file.c_str());
        }
        close(pid_fd);
        exit(0);
    }

    atexit(unlink_pidfile);
    
    // create new process group
    setsid();
    
    // close all descriptors
    int num_fd = getdtablesize();
    for (int fd = 0; fd < num_fd; fd++) {
        if (fd == log_fd) continue;
        close(fd);
    }
    
    // attach stdin, stdout, stderr
    open("/dev/null", O_RDWR);
    dup(log_fd);
    int stderr_fd = dup(log_fd);
    
    // set log file
    latypus_log_file = fdopen(stderr_fd, "w");
    close(log_fd);
}