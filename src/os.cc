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

void os::set_group(std::string os_group)
{
    ssize_t group_buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (group_buflen < 0) {
        log_fatal_exit("sysconf(_SC_GETGR_R_SIZE_MAX) failed: %s", strerror(errno));
    }
    char *group_buf = new char[group_buflen];
    if (!group_buf) {
        log_fatal_exit("getgrnam allocation failed");
    }
    struct group group_ent;
    struct group *group_result;
    getgrnam_r(os_group.c_str(), &group_ent, group_buf, group_buflen, &group_result);
    if (!group_result) {
        log_fatal_exit("getgrnam failed: %s", strerror(errno));
    }
    if (setgid(group_result->gr_gid) < 0) {
        log_fatal_exit("setgid failed: %s", strerror(errno));
    }
    delete [] group_buf;
}

void os::set_user(std::string os_user)
{
    ssize_t passwd_buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (passwd_buflen < 0) {
        log_fatal_exit("sysconf(_SC_GETPW_R_SIZE_MAX) failed: %s", strerror(errno));
    }
    char *passwd_buf = new char[passwd_buflen];
    if (!passwd_buf) {
        log_fatal_exit("getpwnam allocation failed");
    }
    struct passwd passwd_ent;
    struct passwd *passwd_result;
    getpwnam_r(os_user.c_str(), &passwd_ent, passwd_buf, passwd_buflen, &passwd_result);
    if (!passwd_result) {
        log_fatal_exit("getpwnam failed: %s", strerror(errno));
    }
    if (setuid(passwd_result->pw_uid) < 0) {
        log_fatal_exit("setuid failed: %s", strerror(errno));
    }
    delete [] passwd_buf;
}
