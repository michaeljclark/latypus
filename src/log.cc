//
//  logging.cc
//

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <vector>

#include "log.h"

static const int INITIAL_BUFFER_SIZE = 256;

static const char* FATAL_PREFIX = "FATAL";
static const char* ERROR_PREFIX = "ERROR";
static const char* DEBUG_PREFIX = "DEBUG";
static const char* INFO_PREFIX = "INFO";


std::string format_string(const char* fmt, ...)
{
    std::vector<char> buf(INITIAL_BUFFER_SIZE);
    va_list ap;
    
    va_start(ap, fmt);
    int len = vsnprintf(buf.data(), buf.capacity(), fmt, ap);
    va_end(ap);
    
    std::string str;
    if (len >= (int)buf.capacity()) {
        buf.resize(len + 1);
        va_start(ap, fmt);
        vsnprintf(buf.data(), buf.capacity(), fmt, ap);
        va_end(ap);
    }
    str = buf.data();
    
    return str;
}

void log_prefix(const char* prefix, const char* fmt, va_list arg)
{
    std::vector<char> buf(INITIAL_BUFFER_SIZE);
    
    int len = vsnprintf(buf.data(), buf.capacity(), fmt, arg);

    if (len >= (int)buf.capacity()) {
        buf.resize(len + 1);
        vsnprintf(buf.data(), buf.capacity(), fmt, arg);
    }
    
    fprintf(stderr, "%s: %s\n", prefix, buf.data());
}

void log_fatal_exit(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_prefix(FATAL_PREFIX, fmt, ap);
    va_end(ap);
    exit(9);
}

void log_error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_prefix(ERROR_PREFIX, fmt, ap);
    va_end(ap);
}

void log_info(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_prefix(INFO_PREFIX, fmt, ap);
    va_end(ap);
}

void log_debug(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_prefix(DEBUG_PREFIX, fmt, ap);
    va_end(ap);
}
