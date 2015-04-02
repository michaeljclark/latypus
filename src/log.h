//
//  log.h
//

#ifndef log_h
#define log_h

extern FILE* latypus_log_file;

std::string format_string(const char* fmt, ...);
extern void log_prefix(const char* prefix, const char* fmt, va_list arg);
extern void log_fatal_exit(const char* fmt, ...);
extern void log_error(const char* fmt, ...);
extern void log_info(const char* fmt, ...);
extern void log_debug(const char* fmt, ...);

#endif
