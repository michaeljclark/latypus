//
//  logging.cc
//

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cassert>
#include <string>
#include <vector>

#include "log.h"

static const int INITIAL_BUFFER_SIZE = 256;

static const char* FATAL_PREFIX = "FATAL";
static const char* ERROR_PREFIX = "ERROR";
static const char* DEBUG_PREFIX = "DEBUG";
static const char* INFO_PREFIX = "INFO";

FILE* latypus_log_file = nullptr;

std::string format_string(const char* fmt, ...)
{
    std::vector<char> buf;
    va_list args1, args2;
    int len, ret;

    va_start(args1, fmt);
    len = vsnprintf(NULL, 0, fmt, args1);
    assert(len >= 0);
    va_end(args1);

    buf.resize(len + 1);
    va_start(args2, fmt);
    ret = vsnprintf(buf.data(), buf.capacity(), fmt, args2);
    assert(len == ret);
    va_end(args2);
    
    return std::string(buf.data(), len);
}

void log_prefix(const char* prefix, const char* fmt, va_list args1)
{
    std::vector<char> buf;
    va_list args2;
    int len, ret;

    va_copy(args2, args1);

    len = vsnprintf(NULL, 0, fmt, args1);
    assert(len >= 0);
    buf.resize(len + 1);
    ret = vsnprintf(buf.data(), buf.capacity(), fmt, args2);
    assert(len == ret);
    
    if (latypus_log_file) {
        fprintf(latypus_log_file, "%s: %s\n", prefix, buf.data());
        fflush(latypus_log_file);
    } else {
        fprintf(stderr, "%s: %s\n", prefix, buf.data());
    }
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
